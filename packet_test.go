package broadlink

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHelloEncode(t *testing.T) {
	hello := Hello{timezone: 1, year: 2019, second: 59, minute: 21, hour: 19, weekday: 6, day: 12, month: 10, ip: 3232238314, port: 37321}
	actual := hex.EncodeToString(hello.Bytes())
	expected := "5aa5aa555aa5aa5501000000e3073b1513060c0a00000000ea0aa8c0c9910000d1c70000000006000000000000000000"
	assert.Equal(t, expected, actual)
}

func hexdec(s string) []byte {
	s = strings.NewReplacer(" ", "", "\n", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestDeviceParse(t *testing.T) {
	packet := hexdec(`
5a a5 aa 55 5a a5 aa 55  01 00 00 00 e3 07 31 0c
07 02 0f 0a 00 00 00 00  ff ff ff ff 50 00 00 00
4d d3 00 00 00 00 07 00  00 00 00 00 00 00 00 00
cb 51 aa 53 e3 51 92 0a  a8 c0 14 8e 86 42 f7 c8
73 6f 63 6b 65 74 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 02 00
`)
	dev := &Device{}
	dev.Read(packet)
	assert.Equal(t, uint16(0x51e3), dev.device)
	assert.Equal(t, []byte{0x14, 0x8e, 0x86, 0x42, 0xf7, 0xc8}, dev.mac)
}

func TestAuthResponseParse(t *testing.T) {
	packet := hexdec(`
5a a5 aa 55 5a a5 aa 55  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
58 da 00 00 2a 27 e9 03  01 00 14 8e 86 42 f7 c8
00 00 00 00 7c c5 00 00  36 ba 9e ea 63 61 10 4c
fc f2 a8 13 f7 67 a5 ec  f4 bd 64 ef 47 14 ea 2d
8f 36 5d e3 97 ea 81 58
`)
	state := NewState()
	ar := AuthResponse{}
	ar.Read(state, packet)
	assert.Equal(t, uint32(1), ar.id)
	assert.Equal(t, []byte{0x55, 0x65, 0x11, 0x3a, 0x28, 0x71, 0xbf, 0x61, 0xb0, 0x4d, 0xb5, 0x6a, 0x18, 0xb8, 0xd3, 0x4f}, ar.key)
}
