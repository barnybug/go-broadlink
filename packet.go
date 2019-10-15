package broadlink

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

type OutPacket interface {
	Bytes() []byte
}

type Hello struct {
	timezone int32
	year     int16
	second   uint8
	minute   uint8
	hour     uint8
	weekday  uint8
	day      uint8
	month    uint8
	ip       uint32
	port     uint16
}

var header = []byte{0x5a, 0xa5, 0xaa, 0x55, 0x5a, 0xa5, 0xaa, 0x55}

func checksum(data []byte) uint16 {
	// checksum = 0xc0ad

	var check uint16 = 0xbeaf
	for _, c := range data {
		check = (check + uint16(c)) & 0xffff
	}
	return check
}

func commandChecksum(data []byte) uint16 {
	var check uint16 = 0xc0ad
	for _, c := range data {
		check = (check + uint16(c)) & 0xffff
	}
	return check
}

func pad(buf io.ByteWriter, b byte, n int) {
	for i := 0; i < n; i++ {
		buf.WriteByte(b)
	}
}

func padMod(buf *bytes.Buffer, mod int) {
	padding := (mod - (buf.Len() % mod)) % mod
	pad(buf, 0, padding)
}

func (self *Hello) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.Write(header)
	binary.Write(buf, binary.LittleEndian, self.timezone)
	binary.Write(buf, binary.LittleEndian, self.year)
	binary.Write(buf, binary.LittleEndian, self.second)
	binary.Write(buf, binary.LittleEndian, self.minute)
	binary.Write(buf, binary.LittleEndian, self.hour)
	binary.Write(buf, binary.LittleEndian, self.weekday)
	binary.Write(buf, binary.LittleEndian, self.day)
	binary.Write(buf, binary.LittleEndian, self.month)
	pad(buf, 0, 4)
	binary.Write(buf, binary.LittleEndian, self.ip)
	binary.Write(buf, binary.LittleEndian, self.port)
	pad(buf, 0, 2)
	pad(buf, 0, 2) // checksum
	pad(buf, 0, 4)
	binary.Write(buf, binary.LittleEndian, uint16(0x0006)) // command
	pad(buf, 0, 4)
	padMod(buf, 16)

	bytes := buf.Bytes()
	binary.LittleEndian.PutUint16(bytes[0x20:0x22], checksum(bytes))
	return bytes
}

func ip2uint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func NewHello(localAddr net.UDPAddr) *Hello {
	ip := ip2uint32(localAddr.IP)
	port := uint16(localAddr.Port)
	now := time.Now()
	_, offset := now.Local().Zone()
	offset = offset / 3600
	return &Hello{
		timezone: int32(offset),
		year:     int16(now.Year()),
		second:   uint8(now.Second()),
		minute:   uint8(now.Minute()),
		hour:     uint8(now.Hour()),
		weekday:  uint8(now.Weekday()),
		day:      uint8(now.Day()),
		month:    uint8(now.Month()),
		ip:       ip,
		port:     port,
	}
}

type Request interface {
	Name() string
	Command() uint16
	Write(w *bytes.Buffer)
}

type AuthRequest struct {
}

func (self *AuthRequest) Name() string {
	return "Auth"
}

func (self *AuthRequest) Command() uint16 {
	return 0x0065
}

func (self *AuthRequest) Write(buf *bytes.Buffer) {
	pad(buf, 0, 4)
	pad(buf, 0x31, 15)
	pad(buf, 0, 11)
	buf.WriteByte(1)
	pad(buf, 0, 14)
	buf.WriteByte(1)
	pad(buf, 0, 2)
	buf.WriteString("Test  1")
	pad(buf, 0, 25)
}

type Response interface {
	Read(state *State, data []byte) error
}

type AuthResponse struct {
	id  uint32
	key []byte
}

func (ar *AuthResponse) Read(state *State, data []byte) error {
	payload := state.Decrypt(data[0x38:])
	if len(payload) < 0x14 {
		return fmt.Errorf("Auth response packet too short: %d bytes", len(payload))
	}
	// log.Println("Payload:", hex.Dump(payload))
	ar.id = binary.LittleEndian.Uint32(payload[0x00:0x04])
	key := payload[0x04:0x14]
	ar.key = key
	return nil
}

func (ar *AuthResponse) String() string {
	return fmt.Sprintf("AuthResponse{id: %04x mac: %s}", ar.id, hex.EncodeToString(ar.key))
}

type CommandRequest struct {
	flag  uint8 // 1 for read, 2 for write
	state *BGState
}

func (self *CommandRequest) Name() string {
	return "Command"
}

func (command *CommandRequest) Command() uint16 {
	return 0x006a
}

func (command *CommandRequest) Write(buf *bytes.Buffer) {
	// packet format is:
	// 0x00-0x01 length
	// 0x02-0x05 header
	// 0x06-0x07 00
	// 0x08 flag (1 for read or 2 write?)
	// 0x09 unknown (0xb)
	// 0x0a-0x0d length of json
	// 0x0e- json data
	// packet = bytearray(14)
	js := []byte(`{}`)
	if command.state != nil {
		js, _ = json.Marshal(command.state)
	}
	length := 4 + 2 + 2 + 4 + len(js)
	binary.Write(buf, binary.LittleEndian, uint16(length))
	binary.Write(buf, binary.LittleEndian, uint16(0xa5a5))
	binary.Write(buf, binary.LittleEndian, uint16(0x5a5a))
	pad(buf, 0, 2)
	buf.WriteByte(command.flag)
	buf.WriteByte(0x0b)
	binary.Write(buf, binary.LittleEndian, uint32(len(js)))
	buf.Write(js)

	// insert checksum
	b := buf.Bytes()
	checksum := commandChecksum(b[0x08:])
	binary.LittleEndian.PutUint16(b[0x06:0x08], checksum)
}

type BGState struct {
	Pwr           *uint8  `json:"pwr"`
	Pwr1          *uint8  `json:"pwr1"`
	Pwr2          *uint8  `json:"pwr2"`
	Maxworktime   *uint32 `json:"maxworktime"`
	Maxworktime1  *uint32 `json:"maxworktime1"`
	Maxworktime2  *uint32 `json:"maxworktime2"`
	Idcbrightness *uint32 `json:"idcbrightness"`
}

var one = uint8(1)
var zero = uint8(0)
var StateAllOn = &BGState{Pwr: &one}
var StateAllOff = &BGState{Pwr: &zero}
var StatePwr1On = &BGState{Pwr1: &one}
var StatePwr1Off = &BGState{Pwr1: &zero}
var StatePwr2Off = &BGState{Pwr2: &zero}

func (state *BGState) String() string {
	s := ""
	if state.Pwr != nil {
		s += fmt.Sprintf(" pwr:%d", *state.Pwr)
	}
	if state.Pwr1 != nil {
		s += fmt.Sprintf(" pwr1:%d", *state.Pwr1)
	}
	if state.Pwr2 != nil {
		s += fmt.Sprintf(" pwr2:%d", *state.Pwr2)
	}
	if state.Maxworktime != nil {
		s += fmt.Sprintf(" maxworktime:%d", *state.Maxworktime)
	}
	if state.Maxworktime1 != nil {
		s += fmt.Sprintf(" maxworktime1:%d", *state.Maxworktime1)
	}
	if state.Maxworktime2 != nil {
		s += fmt.Sprintf(" maxworktime2:%d", *state.Maxworktime2)
	}
	if state.Idcbrightness != nil {
		s += fmt.Sprintf(" idcbrightness:%d", *state.Idcbrightness)
	}
	return s[1:]
}

type CommandResponse struct {
	state BGState
}

func (cr *CommandResponse) Read(state *State, data []byte) error {
	errcode := binary.LittleEndian.Uint16(data[0x22:0x24])
	if errcode != 0 {
		return fmt.Errorf("Device returned error: %d", errcode)
	}
	payload := state.Decrypt(data[0x38:])
	if len(payload) < 0x0e {
		return fmt.Errorf("Command response packet too short: %d bytes", len(payload))
	}

	len := binary.LittleEndian.Uint32(payload[0xa:0xe])
	if err := json.Unmarshal(payload[0x0e:0x0e+len], &cr.state); err != nil {
		return err
	}
	return nil
}
