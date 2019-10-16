package broadlink

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

type Device struct {
	manager       *Manager
	src           *net.UDPAddr
	conn          *net.UDPConn
	device        uint16
	id            uint32
	count         uint16
	mac           []byte
	state         *State
	authenticated bool
}

func (dev *Device) Read(data []byte) {
	dev.device = binary.LittleEndian.Uint16(data[0x34:0x36])
	dev.mac = data[0x3a:0x40]
}

func (dev *Device) String() string {
	return fmt.Sprintf("Device{type: %02x mac: %s}", dev.device, hex.EncodeToString(dev.mac))
}

func (dev *Device) send(req Request, resp Response) error {
	if !(dev.authenticated || req.Name() == "Auth") {
		return errors.New("device.Auth() has not been called")
	}
	data := dev.encode(req)
	for retry := 0; retry < 5; retry++ {
		n, err := dev.conn.Write(data)
		if err != nil {
			return err
		}
		if dev.manager.debug {
			log.Printf("%s: %s -> %s (%d bytes)\n%s", req.Name(), dev.conn.LocalAddr(), dev.src, n, hex.Dump(data))
		}

		buf := make([]byte, 4096)
		dev.conn.SetDeadline(time.Now().Add(time.Second))
		n, err = dev.conn.Read(buf)
		dev.conn.SetDeadline(time.Time{})
		if err != nil {
			if isTimeout(err) && retry < 4 {
				continue
			}
			return err
		}
		recv := buf[:n]
		if dev.manager.debug {
			log.Printf("%s: %s <- %s (%d bytes)\n%s", req.Name(), dev.conn.LocalAddr(), dev.src, n, hex.Dump(recv))
		}

		if err := resp.Read(dev.state, recv); err != nil {
			return err
		}
	}
	return nil
}

func (dev *Device) Auth() error {
	if dev.authenticated {
		return errors.New("Already authenticated")
	}
	var err error
	dev.conn, err = net.DialUDP("udp4", nil, dev.src)
	if err != nil {
		return err
	}
	req := &AuthRequest{}
	resp := &AuthResponse{}
	if err := dev.send(req, resp); err != nil {
		return err
	}
	dev.authenticated = true
	if dev.manager.debug {
		log.Println("Negotiated key:", hex.EncodeToString(resp.key))
	}
	dev.state.key = resp.key // use negotiated key ongoing
	dev.id = resp.id

	return nil
}

func (dev *Device) GetState() (*BGState, error) {
	req := &CommandRequest{flag: 1, state: nil}
	resp := &CommandResponse{}
	if err := dev.send(req, resp); err != nil {
		return nil, err
	}
	return &resp.state, nil
}

func (dev *Device) SetState(state *BGState) (*BGState, error) {
	req := &CommandRequest{flag: 2, state: state}
	resp := &CommandResponse{}
	if err := dev.send(req, resp); err != nil {
		return nil, err
	}
	return &resp.state, nil
}

func (dev *Device) encode(req Request) []byte {
	dev.count++
	// prepare request
	payloadBuf := bytes.NewBuffer(req.Payload())
	padMod(payloadBuf, 16)
	plaintext := payloadBuf.Bytes()
	// construct packet
	buf := new(bytes.Buffer)
	buf.Write(header)
	pad(buf, 0, 28)
	binary.Write(buf, binary.LittleEndian, uint16(0x51e3))
	binary.Write(buf, binary.LittleEndian, uint16(req.Command()))
	binary.Write(buf, binary.LittleEndian, dev.count)
	buf.Write(dev.mac)
	binary.Write(buf, binary.LittleEndian, dev.id)
	binary.Write(buf, binary.LittleEndian, checksum(plaintext))
	pad(buf, 0, 2)

	ciphertext := dev.state.Encrypt(plaintext)
	buf.Write(ciphertext)

	bytes := buf.Bytes()
	binary.LittleEndian.PutUint16(bytes[0x20:0x22], checksum(bytes))
	return bytes
}
