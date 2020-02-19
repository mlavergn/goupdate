package main

import (
	"log"
	"os"
	"time"

	"github.com/mlavergn/goupdate/src/update"
)

// Version export
const Version = "0.9.0"

func check(updater *update.Update, current *update.SemanticVersion) {
	release := updater.Check(current)
	if release != nil {
		result := updater.Update(current, release)
		log.Println("Udpated, restart required", result)
	}

}

func autoupdate(updater *update.Update, current *update.SemanticVersion) {
	// check for update every 1 minute
	updater.AutoUpdate(current, 1*time.Minute, func(release *update.SemanticVersion) {
		log.Println("Update ready")
		os.Exit(0)
	})
}

func main() {
	current := update.NewSemanticVersion(Version)
	updater := update.NewGitHubUpdate("mlavergn", "godaemon", "", false)
	check(updater, current)
	// autoupdate(update, current)

	<-time.After(5 * time.Minute)
}
