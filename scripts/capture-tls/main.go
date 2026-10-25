package main

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Sn0wo2/caelum"
)

type clientHello struct {
	version      uint16
	handshakeLen int
	ciphers      []uint16
	extensions   []uint16
	curves       []uint16
	points       []byte
	sni          string
	alpn         []string
}

func main() {
	logger := caelum.New(caelum.Config{})

	out := flag.String("o", "clienthello.bin", "output file")
	listen := flag.String("listen", "localhost:19104", "listen address")
	timeout := flag.Duration("timeout", 10*time.Second, "capture timeout")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage: go run ./scripts/capture-tls [options] [-- command...]

  -o <file>       output file (default clienthello.bin)
  -listen <addr>  listen address (default localhost:19104)
  -timeout <dur>  capture timeout (default 10s)

The command receives CAPTURE_URL, CAPTURE_HOST and CAPTURE_PORT in its
environment. Every "{url}" argument is replaced with the capture URL.
Without "-- command", the tool waits for a client to connect.
`)
	}

	flag.Parse()

	if err := func() error {
		host, port, err := net.SplitHostPort(*listen)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		urlHost := host
		if urlHost == "" || urlHost == "0.0.0.0" || urlHost == "::" {
			urlHost = "localhost"
		}

		if strings.Contains(urlHost, ":") {
			urlHost = "[" + urlHost + "]"
		}

		url := "https://" + urlHost + ":" + port + "/"

		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		defer func() { _ = ln.Close() }()

		fmt.Printf("listening on %s\n", url)

		if len(flag.Args()) == 0 {
			fmt.Println("waiting for a TLS client...")
		}

		results := make(chan []byte, 1)

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}

				go func(conn net.Conn) {
					defer func() { _ = conn.Close() }()

					_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

					header := make([]byte, 5)
					if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x16 {
						return
					}

					record := make([]byte, 5+int(binary.BigEndian.Uint16(header[3:])))
					copy(record, header)

					if _, err := io.ReadFull(conn, record[5:]); err != nil {
						return
					}

					if len(record) < 6 || record[5] != 0x01 {
						return
					}

					select {
					case results <- record:
					default:
					}
				}(conn)
			}
		}()

		if args := flag.Args(); len(args) > 0 {
			for i := range args {
				args[i] = strings.ReplaceAll(args[i], "{url}", url)
			}

			cmd := exec.Command(args[0], args[1:]...)

			cmd.Env = append(os.Environ(),
				"CAPTURE_URL="+url,
				"CAPTURE_HOST="+host,
				"CAPTURE_PORT="+port,
			)
			cmd.Stdout = os.Stdout

			cmd.Stderr = os.Stderr

			cmd.Stdin = os.Stdin
			if err := cmd.Start(); err != nil {
				return err
			}
			defer func() { _ = cmd.Process.Kill() }()
		}

		select {
		case record := <-results:
			if err := os.WriteFile(*out, record, 0o600); err != nil {
				return err
			}

			fmt.Printf("captured %d bytes -> %s\n", len(record), *out)
			fmt.Printf("record=%x\n", record[:5])

			hello, err := parseClientHello(record)
			if err != nil {
				logger.Error("parse ClientHello", "error", err)

				return nil
			}

			ciphers := make([]string, 0, len(hello.ciphers))
			for _, value := range hello.ciphers {
				if value&0x0f0f != 0x0a0a {
					ciphers = append(ciphers, strconv.Itoa(int(value)))
				}
			}

			extensions := make([]string, 0, len(hello.extensions))
			for _, value := range hello.extensions {
				if value&0x0f0f != 0x0a0a {
					extensions = append(extensions, strconv.Itoa(int(value)))
				}
			}

			curves := make([]string, 0, len(hello.curves))
			for _, value := range hello.curves {
				if value&0x0f0f != 0x0a0a {
					curves = append(curves, strconv.Itoa(int(value)))
				}
			}

			points := make([]string, 0, len(hello.points))
			for _, value := range hello.points {
				points = append(points, strconv.Itoa(int(value)))
			}

			raw := fmt.Sprintf("%d,%s,%s,%s,%s",
				hello.version,
				strings.Join(ciphers, "-"),
				strings.Join(extensions, "-"),
				strings.Join(curves, "-"),
				strings.Join(points, "-"),
			)
			fmt.Printf("ja3=%x\n", md5.Sum([]byte(raw)))

			sni := hello.sni
			if sni == "" {
				sni = "(none)"
			}

			alpn := strings.Join(hello.alpn, ",")
			if alpn == "" {
				alpn = "(none)"
			}

			fmt.Printf("sni=%s alpn=%s\n", sni, alpn)
			fmt.Printf("tls=%04x handshake=%d ciphers=%d extensions=%d\n",
				hello.version, hello.handshakeLen, len(hello.ciphers), len(hello.extensions))
		case <-time.After(*timeout):
			return fmt.Errorf("timeout after %s waiting for a ClientHello", *timeout)
		}

		return nil
	}(); err != nil {
		logger.Error("capture TLS", "error", err)
		os.Exit(1)
	}
}

func parseClientHello(record []byte) (*clientHello, error) {
	if len(record) < 9 || record[0] != 0x16 || record[5] != 0x01 {
		return nil, errors.New("not a TLS ClientHello")
	}

	hs := record[5:]

	handshakeLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if handshakeLen+4 > len(hs) {
		return nil, io.ErrUnexpectedEOF
	}

	q := 4
	if q+2+32+1 > len(hs) {
		return nil, io.ErrUnexpectedEOF
	}

	hello := &clientHello{
		version:      binary.BigEndian.Uint16(hs[q:]),
		handshakeLen: handshakeLen,
	}
	q += 2 + 32

	sessionLen := int(hs[q])

	q++
	if q+sessionLen+2 > len(hs) {
		return nil, io.ErrUnexpectedEOF
	}

	q += sessionLen

	cipherLen := int(binary.BigEndian.Uint16(hs[q:]))

	q += 2
	if q+cipherLen+1 > len(hs) {
		return nil, io.ErrUnexpectedEOF
	}

	for i := 0; i < cipherLen; i += 2 {
		hello.ciphers = append(hello.ciphers, binary.BigEndian.Uint16(hs[q+i:]))
	}

	q += cipherLen

	compressionLen := int(hs[q])

	q++
	if q+compressionLen+2 > len(hs) {
		return nil, io.ErrUnexpectedEOF
	}

	q += compressionLen

	extensionsLen := int(binary.BigEndian.Uint16(hs[q:]))

	q += 2
	if q+extensionsLen > len(hs) {
		return nil, io.ErrUnexpectedEOF
	}

	end := q + extensionsLen

	for q+4 <= end {
		extensionType := binary.BigEndian.Uint16(hs[q:])
		extensionLen := int(binary.BigEndian.Uint16(hs[q+2:]))

		q += 4
		if q+extensionLen > end {
			return nil, io.ErrUnexpectedEOF
		}

		data := hs[q : q+extensionLen]
		q += extensionLen

		hello.extensions = append(hello.extensions, extensionType)

		switch extensionType {
		case 0:
			if len(data) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(data[3:]))
				if 5+nameLen <= len(data) {
					hello.sni = string(data[5 : 5+nameLen])
				}
			}
		case 16:
			for i := 2; i < len(data); {
				n := int(data[i])

				i++
				if i+n > len(data) {
					break
				}

				hello.alpn = append(hello.alpn, string(data[i:i+n]))
				i += n
			}
		case 10:
			if len(data) >= 2 {
				n := int(binary.BigEndian.Uint16(data))
				for i := 2; i+1 < 2+n && i+1 < len(data); i += 2 {
					hello.curves = append(hello.curves, binary.BigEndian.Uint16(data[i:]))
				}
			}
		case 11:
			if len(data) >= 1 {
				n := int(data[0])
				if 1+n <= len(data) {
					hello.points = append(hello.points, data[1:1+n]...)
				}
			}
		}
	}

	return hello, nil
}
