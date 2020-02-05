package main

import (
	"log"
	"time"

	"github.com/mlavergn/goupdate/src/update"
)

// Version export
const Version = "0.9.0"

func main() {
	update := update.NewGitHubUpdate("mlavergn", "godaemon", "")
	release := update.Check(Version)
	if release != nil {
		result := update.Update(release)
		log.Println("Udpated, restart required", result)
	}

	// check for update every X minutes
	// update.AutoUpdate(Version, 1, func(version string) {
	// 	log.Println("Update ready")
	// 	os.Exit(0)
	// })
	<-time.After(5 * time.Minute)
}
