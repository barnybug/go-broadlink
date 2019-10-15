package broadlink

import (
	"encoding/hex"
	"log"
	"net"
	"time"
)

type Manager struct {
	debug      bool
	Discovered chan *Device
}

func NewManager(debug bool) *Manager {
	return &Manager{debug: debug, Discovered: make(chan *Device, 16)}
}

func isTimeout(err error) bool {
	if ope, ok := err.(*net.OpError); ok && ope.Timeout() {
		// deadline passed
		return true
	}
	return false
}

func (man *Manager) Discover(timeout time.Duration) error {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 80}
	hello := NewHello(*broadcastAddr)
	req := hello.Bytes()
	_, err = conn.WriteToUDP(req, broadcastAddr)
	if err != nil {
		return err
	}
	if man.debug {
		log.Printf("Discover: %s -> %s (%d bytes)\n%s", conn.LocalAddr(), broadcastAddr, len(req), hex.Dump(req))
	}

	resp := make([]byte, 2048)
	for {
		conn.SetDeadline(deadline)
		n, src, err := conn.ReadFromUDP(resp)
		if err != nil {
			if isTimeout(err) {
				// deadline passed
				if man.debug {
					log.Println("Discovery timeout")
				}
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		data := resp[:n]
		if man.debug {
			log.Printf("Discover: %s <- %s (%d bytes)\n%s", conn.LocalAddr(), src, len(data), hex.Dump(data))
		}
		dev := Device{manager: man, src: src, state: NewState()}
		dev.Read(data)
		man.Discovered <- &dev
	}
}
