package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"tls-override/utils"

	"github.com/Sn0wo2/caelum"
)

func main() {
	logger := caelum.New(caelum.Config{})

	listen := flag.String("listen", "127.0.0.1:8787", "listen address")

	flag.Parse()

	if _, err := resolveFingerprint("bun", httpVersionAuto, false); err != nil {
		logger.Error("initialize fingerprint", "error", err)
		os.Exit(1)
	}

	cache := &transportCache{}
	plain := &http.Transport{DisableCompression: true}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError := func(code int, message string) {
			encoder := json.NewEncoder(w)
			if r.URL.Query().Has("pretty") {
				encoder.SetIndent("", "  ")
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)

			if err := encoder.Encode(struct {
				Msg string `json:"msg"`
			}{Msg: message}); err != nil {
				logger.Error("write error response", "error", err)
			}
		}

		raw := strings.TrimSpace(r.Header.Get("Tls-Override"))
		if raw == "" {
			writeError(http.StatusBadRequest, "missing tls-override header")

			return
		}

		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}

		target, err := url.Parse(raw)
		if err != nil {
			writeError(http.StatusBadRequest, fmt.Sprintf("invalid target URL: %v", err))

			return
		}

		target.Scheme = strings.ToLower(target.Scheme)
		if target.Scheme != "http" && target.Scheme != "https" {
			writeError(http.StatusBadRequest, fmt.Sprintf("unsupported target scheme %q", target.Scheme))

			return
		}

		if target.Host == "" {
			writeError(http.StatusBadRequest, "target URL has no host")

			return
		}

		target.Fragment = ""
		switch {
		case target.Path == "" || target.Path == "/":
			target.Path = r.URL.Path
			if target.Path == "" {
				target.Path = "/"
			}
		case r.URL.Path != "" && r.URL.Path != "/":
			target.Path = strings.TrimSuffix(target.Path, "/") + "/" + strings.TrimPrefix(r.URL.Path, "/")
		}

		target.RawPath = ""
		if target.RawQuery == "" {
			target.RawQuery = r.URL.RawQuery
		}

		fingerprintName := strings.TrimSpace(r.Header.Get("Tls-Fingerprint"))
		if fingerprintName == "" {
			fingerprintName = "bun"
		}

		version := httpVersionAuto

		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Tls-Http-Version"))) {
		case "", "auto":
		case "1", "1.1", "http/1.1", "http1", "h1":
			version = httpVersion11
		case "2", "2.0", "http/2", "http/2.0", "http2", "h2":
			version = httpVersion2
		default:
			writeError(http.StatusBadRequest, fmt.Sprintf("invalid tls-http-version %q (use auto, 1.1, or 2)", r.Header.Get("Tls-Http-Version")))

			return
		}

		insecure := false

		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Tls-Insecure"))) {
		case "", "false", "0":
		case "true", "1":
			insecure = true
		default:
			writeError(http.StatusBadRequest, fmt.Sprintf("invalid tls-insecure %q (use true or false)", r.Header.Get("Tls-Insecure")))

			return
		}

		var transport http.RoundTripper = plain
		if target.Scheme == "https" {
			transport, err = cache.transport(fingerprintName, version, insecure)
			if err != nil {
				writeError(http.StatusBadRequest, err.Error())

				return
			}
		}

		out := r.Clone(r.Context())
		out.URL = target
		out.RequestURI = ""
		out.Host = utils.HostHeader(target)
		out.GetBody = nil
		out.TransferEncoding = nil
		out.Close = false
		utils.StripHopByHop(out.Header)
		out.Header.Del("Host")
		out.Header.Del("Content-Length")
		out.Header.Del("Tls-Override")
		out.Header.Del("Tls-Fingerprint")
		out.Header.Del("Tls-Http-Version")
		out.Header.Del("Tls-Insecure")

		if origin := out.Header.Get("Origin"); origin != "" {
			if parsed, err := url.Parse(origin); err == nil && strings.EqualFold(parsed.Host, r.Host) {
				out.Header.Set("Origin", target.Scheme+"://"+out.Host)
			}
		}

		if referer := out.Header.Get("Referer"); referer != "" {
			if parsed, err := url.Parse(referer); err == nil && strings.EqualFold(parsed.Host, r.Host) {
				parsed.Scheme = target.Scheme
				parsed.Host = target.Host
				out.Header.Set("Referer", parsed.String())
			}
		}

		resp, err := transport.RoundTrip(out)
		if err != nil {
			writeError(http.StatusBadGateway, err.Error())

			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		headers := resp.Header.Clone()
		utils.StripHopByHop(headers)

		for name, values := range headers {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}

		w.WriteHeader(resp.StatusCode)

		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					return
				}

				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
			}

			if err != nil {
				if !errors.Is(err, io.EOF) {
					logger.Error("read upstream response", "method", r.Method, "path", r.URL.Path, "error", err)
				}

				return
			}
		}
	})

	logger.Info("tls-override listening", "url", "http://"+*listen)

	if err := (&http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}).ListenAndServe(); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}
