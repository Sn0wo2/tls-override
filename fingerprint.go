package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"tls-override/bunhello"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type httpVersion int

const (
	httpVersionAuto httpVersion = iota
	httpVersion11
	httpVersion2
)

func parseHTTPVersion(raw string) (httpVersion, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return httpVersionAuto, nil
	case "1", "1.1", "http/1.1", "http1", "h1":
		return httpVersion11, nil
	case "2", "2.0", "http/2", "http/2.0", "http2", "h2":
		return httpVersion2, nil
	default:
		return 0, fmt.Errorf("invalid tls-http-version %q (use auto, 1.1, or 2)", raw)
	}
}

type fingerprint struct {
	name     string
	newSpec  func() (*utls.ClientHelloSpec, error)
	helloID  *utls.ClientHelloID
	alpn     []string
	insecure bool
}

func resolveFingerprint(name string, version httpVersion, insecure bool) (*fingerprint, error) {
	key := strings.ToLower(strings.TrimSpace(name))

	key = strings.ReplaceAll(key, "-", "_")
	if key == "" {
		key = "bun"
	}

	var (
		id          utls.ClientHelloID
		usesBunSpec bool
		helloID     *utls.ClientHelloID
		alpn        []string
	)

	switch key {
	case "bun":
		usesBunSpec = true
	case "chrome", "chrome_auto":
		id = utls.HelloChrome_Auto
	case "chrome120":
		id = utls.HelloChrome_120
	case "chrome133":
		id = utls.HelloChrome_133
	case "firefox", "firefox_auto":
		id = utls.HelloFirefox_Auto
	case "safari", "safari_auto":
		id = utls.HelloSafari_Auto
	case "ios", "ios_auto":
		id = utls.HelloIOS_Auto
	case "android", "okhttp":
		id = utls.HelloAndroid_11_OkHttp
	case "edge", "edge_auto":
		id = utls.HelloEdge_Auto
	case "random", "randomized":
		id = utls.HelloRandomizedALPN
	case "golang", "go":
		id := utls.HelloGolang
		helloID = &id
		alpn = []string{"h2", "http/1.1"}
	default:
		return nil, fmt.Errorf("unknown fingerprint %q", name)
	}

	switch version {
	case httpVersionAuto:
	case httpVersion11:
		alpn = []string{"http/1.1"}
	case httpVersion2:
		alpn = []string{"h2"}
	}

	if helloID != nil {
		return &fingerprint{
			name:     key,
			helloID:  helloID,
			alpn:     alpn,
			insecure: insecure,
		}, nil
	}

	newSpec := func() (*utls.ClientHelloSpec, error) {
		var (
			spec *utls.ClientHelloSpec
			err  error
		)
		if usesBunSpec {
			spec, err = bunhello.Spec()
		} else {
			var generated utls.ClientHelloSpec

			generated, err = utls.UTLSIdToSpec(id)
			if err == nil {
				spec = &generated
			}
		}

		if err != nil {
			return nil, err
		}

		if version != httpVersionAuto {
			found := false

			for i, extension := range spec.Extensions {
				if _, ok := extension.(*utls.ALPNExtension); ok {
					spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: alpn}
					found = true

					break
				}
			}

			if !found {
				spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: alpn})
			}
		}

		return spec, nil
	}

	spec, err := newSpec()
	if err != nil {
		return nil, fmt.Errorf("fingerprint %s: %w", key, err)
	}

	alpn = nil

	for _, extension := range spec.Extensions {
		if extension, ok := extension.(*utls.ALPNExtension); ok {
			alpn = extension.AlpnProtocols

			break
		}
	}

	return &fingerprint{
		name:     key,
		newSpec:  newSpec,
		alpn:     alpn,
		insecure: insecure,
	}, nil
}

func (f *fingerprint) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: f.insecure,
		NextProtos:         f.alpn,
	}

	conn := utls.UClient(raw, config, utls.HelloCustom)
	if f.helloID != nil {
		conn = utls.UClient(raw, config, *f.helloID)
	} else {
		spec, err := f.newSpec()
		if err != nil {
			_ = raw.Close()

			return nil, err
		}

		foundSNI := false

		for _, extension := range spec.Extensions {
			if sni, ok := extension.(*utls.SNIExtension); ok {
				sni.ServerName = host
				foundSNI = true

				break
			}
		}

		if !foundSNI {
			spec.Extensions = append([]utls.TLSExtension{&utls.SNIExtension{ServerName: host}}, spec.Extensions...)
		}

		if err := conn.ApplyPreset(spec); err != nil {
			_ = raw.Close()

			return nil, err
		}
	}

	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()

		return nil, err
	}

	return conn, nil
}

type clientKey struct {
	name     string
	version  httpVersion
	insecure bool
}

type transportCache struct {
	mu      sync.Mutex
	clients map[clientKey]*http.Client
}

func (c *transportCache) client(name string, version httpVersion, insecure bool) (*http.Client, error) {
	fp, err := resolveFingerprint(name, version, insecure)
	if err != nil {
		return nil, err
	}

	key := clientKey{name: fp.name, version: version, insecure: insecure}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.clients == nil {
		c.clients = make(map[clientKey]*http.Client)
	}

	if client, ok := c.clients[key]; ok {
		return client, nil
	}

	var transport http.RoundTripper
	if slices.Contains(fp.alpn, "h2") {
		//nolint:staticcheck // Custom uTLS connections require the standalone HTTP/2 transport.
		transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return fp.dial(ctx, network, addr)
			},
			DisableCompression: true,
		}
	} else {
		transport = &http.Transport{
			DialTLSContext:     fp.dial,
			TLSNextProto:       map[string]func(string, *tls.Conn) http.RoundTripper{},
			DisableCompression: true,
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	c.clients[key] = client

	return client, nil
}
