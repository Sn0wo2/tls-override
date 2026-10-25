package main

import (
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
	"github.com/labstack/echo/v4"
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
	plain := &http.Client{
		Transport: &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		code := http.StatusInternalServerError
		message := http.StatusText(code)

		var httpErr *echo.HTTPError
		if errors.As(err, &httpErr) {
			code = httpErr.Code
			message = fmt.Sprint(httpErr.Message)
		}

		if err := c.JSON(code, struct {
			Msg  string `json:"msg"`
			Data any    `json:"data,omitempty"`
		}{Msg: message}); err != nil {
			logger.Error("write error response", "error", err)
		}
	}
	e.Any("/*", func(c echo.Context) error {
		r := c.Request()
		w := c.Response()

		raw := strings.TrimSpace(r.Header.Get("Tls-Override"))
		if raw == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing tls-override header")
		}

		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}

		target, err := url.Parse(raw)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid target URL: %v", err))
		}

		target.Scheme = strings.ToLower(target.Scheme)
		if target.Scheme != "http" && target.Scheme != "https" {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unsupported target scheme %q", target.Scheme))
		}

		if target.Host == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "target URL has no host")
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
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid tls-http-version %q (use auto, 1.1, or 2)", r.Header.Get("Tls-Http-Version")))
		}

		insecure := false

		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Tls-Insecure"))) {
		case "", "false", "0":
		case "true", "1":
			insecure = true
		default:
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid tls-insecure %q (use true or false)", r.Header.Get("Tls-Insecure")))
		}

		client := plain
		if target.Scheme == "https" {
			client, err = cache.client(fingerprintName, version, insecure)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}
		}

		out := r.Clone(r.Context())
		out.URL = target
		out.RequestURI = ""
		out.Host = utils.HostHeader(target)
		out.Body = r.Body
		out.GetBody = nil
		out.ContentLength = r.ContentLength
		out.TransferEncoding = nil
		out.Close = false
		out.Header = r.Header.Clone()
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

		resp, err := client.Transport.RoundTrip(out)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadGateway, err.Error())
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
					return writeErr
				}

				w.Flush()
			}

			if err != nil {
				if !errors.Is(err, io.EOF) {
					logger.Error("read upstream response", "method", r.Method, "path", r.URL.Path, "error", err)
				}

				return nil
			}
		}
	})

	logger.Info("tls-override listening", "url", "http://"+*listen)

	if err := e.StartServer(&http.Server{
		Addr:              *listen,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}
