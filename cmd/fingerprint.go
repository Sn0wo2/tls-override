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

type fingerprint struct {
	newSpec  func() (*utls.ClientHelloSpec, error)
	helloID  *utls.ClientHelloID
	alpn     []string
	insecure bool
}

func resolveFingerprint(name string, version httpVersion, insecure bool) (*fingerprint, error) {
	key := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
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
			helloID:  helloID,
			alpn:     alpn,
			insecure: insecure,
		}, nil
	}

	newSpec := func() (*utls.ClientHelloSpec, error) {
		var spec *utls.ClientHelloSpec

		if usesBunSpec {
			var err error

			spec, err = bunhello.Spec()
			if err != nil {
				return nil, err
			}
		} else {
			generated, err := utls.UTLSIdToSpec(id)
			if err != nil {
				return nil, err
			}

			spec = &generated
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

	var conn *utls.UConn
	if f.helloID != nil {
		conn = utls.UClient(raw, config, *f.helloID)
	} else {
		conn = utls.UClient(raw, config, utls.HelloCustom)

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

type transportKey struct {
	name     string
	version  httpVersion
	insecure bool
}

type transportCache struct {
	mu         sync.Mutex
	transports map[transportKey]http.RoundTripper
}

func (c *transportCache) transport(name string, version httpVersion, insecure bool) (http.RoundTripper, error) {
	key := transportKey{
		name:     strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_"),
		version:  version,
		insecure: insecure,
	}
	if key.name == "" {
		key.name = "bun"
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if transport, ok := c.transports[key]; ok {
		return transport, nil
	}

	fp, err := resolveFingerprint(name, version, insecure)
	if err != nil {
		return nil, err
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

	if c.transports == nil {
		c.transports = make(map[transportKey]http.RoundTripper)
	}

	c.transports[key] = transport

	return transport, nil
}
