package bunhello

import (
	_ "embed"

	utls "github.com/refraction-networking/utls"
)

//go:embed bun-clienthello.bin
var raw []byte

func Spec() (*utls.ClientHelloSpec, error) {
	return (&utls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(raw)
}
