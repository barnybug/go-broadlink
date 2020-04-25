package main

import (
	"log"
	"time"

	"github.com/barnybug/broadlink"
)

func main() {
	log.Println("Discovering...")
	man := broadlink.NewManager(false)
	go func() {
		err := man.Discover(30 * time.Second)
		if err != nil {
			log.Fatalln(err)
		}
		close(man.Discovered)
	}()
	for device := range man.Discovered {
		log.Printf("Discovered: %s", device)
		err := device.Auth()
		if err != nil {
			log.Println(err)
			continue
		} else {
			log.Printf("Authenticated: %s", device)
		}

		log.Println(device.SetState(broadlink.StateAllOff))
		time.Sleep(time.Second)
		log.Println(device.SetState(broadlink.StatePwr1On))
		time.Sleep(time.Second)
		log.Println(device.SetState(broadlink.StatePwr1Off))
		time.Sleep(time.Second)
		log.Println(device.SetState(broadlink.StatePwr2On))
		time.Sleep(time.Second)
		log.Println(device.SetState(broadlink.StatePwr2Off))
	}
}
