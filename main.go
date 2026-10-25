package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"tls-override/utils"
)

type proxy struct {
	cache *transportCache
	plain *http.Client
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "listen address")

	flag.Parse()

	if _, err := resolveFingerprint("bun", httpVersionAuto, false); err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr: *listen,
		Handler: &proxy{
			cache: &transportCache{},
			plain: &http.Client{
				Transport: &http.Transport{DisableCompression: true},
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	log.Printf("tls-override listening on http://%s (settings via tls-* headers)", *listen)
	log.Fatal(server.ListenAndServe())
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.Header.Get("Tls-Override"))
	if raw == "" {
		http.Error(w, "missing tls-override header", http.StatusBadRequest)

		return
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	target, err := url.Parse(raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid target URL: %v", err), http.StatusBadRequest)

		return
	}

	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		http.Error(w, fmt.Sprintf("unsupported target scheme %q", target.Scheme), http.StatusBadRequest)

		return
	}

	if target.Host == "" {
		http.Error(w, "target URL has no host", http.StatusBadRequest)

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

	version, err := parseHTTPVersion(r.Header.Get("Tls-Http-Version"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	insecure := false

	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Tls-Insecure"))) {
	case "", "false", "0":
	case "true", "1":
		insecure = true
	default:
		http.Error(w, fmt.Sprintf("invalid tls-insecure %q (use true or false)", r.Header.Get("Tls-Insecure")), http.StatusBadRequest)

		return
	}

	client := p.plain
	if target.Scheme == "https" {
		client, err = p.cache.client(fingerprintName, version, insecure)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
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
		http.Error(w, err.Error(), http.StatusBadGateway)

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

	flusher, _ := w.(http.Flusher)

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}

			if flusher != nil {
				flusher.Flush()
			}
		}

		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("%s %s: %v", url.QueryEscape(r.Method), url.QueryEscape(r.URL.Path), err)
			}

			return
		}
	}
}
