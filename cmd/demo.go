package main

import (
	"github.com/mlavergn/goupdate/src/update"
)

// Version export
const Version = "0.9.0"

func main() {
	update.Check(Version)
}
