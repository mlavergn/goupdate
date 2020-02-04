package main

import (
	"github.com/mlavergn/goupdate/src/update"
)

// Version export
const Version = "1.3.0"

func main() {
	url := "https://api.github.com/repos/mlavergn/godaemon/releases/latest"
	update := update.NewGoUpdate(url)
	update.Check(Version)
}
