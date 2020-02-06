package main

import (
	"log"
	"time"

	"github.com/mlavergn/goupdate/src/update"
)

// Version export
const Version = "0.9.0"

func main() {
	hubupdate := update.NewGitHubUpdate("mlavergn", "godaemon", "")
	current := update.NewSemanticVersion(Version)
	release := hubupdate.Check(*current)
	if release != nil {
		result := hubupdate.Update(release)
		log.Println("Udpated, restart required", result)
	}

	// check for update every X minutes
	// update.AutoUpdate(current, 1*time.Minute, func(version string) {
	// 	log.Println("Update ready")
	// 	os.Exit(0)
	// })
	<-time.After(5 * time.Minute)
}
