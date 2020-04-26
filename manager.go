package broadlink

import (
	"encoding/hex"
	"errors"
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

func getLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.IPv4zero, errors.New("Unable to find IP address. Ensure you're connected to a network")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func (man *Manager) Discover(timeout time.Duration) error {
	lip, err := getLocalIP()
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lip})
	if err != nil {
		return err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if man.debug {
		log.Printf("Local address: %s", localAddr)
	}

	deadline := time.Now().Add(timeout)
	deadlineTimer := time.NewTimer(timeout)
	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 80}

	go func() {
		ticker := time.NewTicker(time.Second)
		for {
			hello := NewHello(*localAddr)
			req := hello.Bytes()
			_, err = conn.WriteToUDP(req, broadcastAddr)
			if err != nil {
				log.Fatalln(err)
				return
			}
			if man.debug {
				log.Printf("Discover: %s -> %s (%d bytes)\n%s", localAddr, broadcastAddr, len(req), hex.Dump(req))
			}

			select {
			case <-ticker.C:
				continue
			case <-deadlineTimer.C:
				return
			}
		}
	}()

	resp := make([]byte, 2048)
	seen := map[string]bool{}
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
			log.Printf("Discovered: %s <- %s (%d bytes)\n%s", localAddr, src, len(data), hex.Dump(data))
		}
		dev := Device{manager: man, src: src, state: NewState()}
		dev.Read(data)
		mac := dev.MacString()
		if !seen[mac] {
			man.Discovered <- &dev
			seen[mac] = true
		}
	}
}
