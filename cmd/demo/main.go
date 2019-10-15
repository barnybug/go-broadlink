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
		for device := range man.Discovered {
			log.Printf("Discovered: %s", device)
			err := device.Auth()
			if err != nil {
				log.Println(err)
				continue
			}

			state, err := device.GetState()
			if err == nil {
				log.Println("State:", state)
			} else {
				log.Println(err)
				continue
			}

			device.SetState(broadlink.StateAllOff)
			time.Sleep(time.Second)
			device.SetState(broadlink.StatePwr1On)
			time.Sleep(time.Second)
			device.SetState(broadlink.StatePwr1Off)
			time.Sleep(time.Second)
			device.SetState(broadlink.StatePwr2On)
			time.Sleep(time.Second)
			device.SetState(broadlink.StatePwr2Off)
		}
	}()
	man.Discover(5 * time.Second)
}
