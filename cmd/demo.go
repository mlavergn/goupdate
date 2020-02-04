package main

import (
	"github.com/mlavergn/goupdate/src/update"
	"log"
	"time"
)

// Version export
const Version = "0.9.0"

func main() {
	url := "https://api.github.com/repos/mlavergn/godaemon/releases/latest"
	update := update.NewUpdate(url)
	release := update.Check(Version)
	if release != nil {
		result := update.Update(release)
		log.Println("Udpated, restart required", result)
	}
	// update.AutoUpdate(Version, 1)
	<-time.After(5 * time.Minute)
}
