package main

import (
	"log"
	"os"
	"time"

	"github.com/mlavergn/goupdate/src/update"
)

// Version export
const Version = "0.9.0"

func check(update *update.Update, current update.SemanticVersion) {
	release := update.Check(current)
	if release != nil {
		result := update.Update(release)
		log.Println("Udpated, restart required", result)
	}

}

func autoupdate(update *update.Update, current update.SemanticVersion) {
	// check for update every 1 minute
	update.AutoUpdate(current, 1*time.Minute, func(version string) {
		log.Println("Update ready")
		os.Exit(0)
	})
}

func main() {
	current := *update.NewSemanticVersion(Version)
	update := update.NewGitHubUpdate("mlavergn", "godaemon", "")
	check(update, current)
	// autoupdate(update, current)

	<-time.After(5 * time.Minute)
}
