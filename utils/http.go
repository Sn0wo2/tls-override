package utils

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func HostHeader(target *url.URL) string {
	host := target.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	port := target.Port()
	if port == "" ||
		(target.Scheme == "https" && port == "443") ||
		(target.Scheme == "http" && port == "80") {
		return host
	}

	return net.JoinHostPort(target.Hostname(), port)
}

func StripHopByHop(header http.Header) {
	for _, connection := range header.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}

	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}
