package update

import (
	"fmt"
	"io/ioutil"
	oslog "log"
	"os"
)

// Version export
const Version = "0.0.1"

// DEBUG flag for runtime
const DEBUG = false

// stand-in for system logger
var log *oslog.Logger

// debug logger
var dlog *oslog.Logger
var dfilter *string

// null logger
var lognull *oslog.Logger

// Config export
func Config(debug bool) {
	if debug {
		log = oslog.New(os.Stderr, "GoUpdate ", oslog.Ltime|oslog.Lshortfile)
	} else {
		log = lognull
	}
}

func init() {
	lognull = oslog.New(ioutil.Discard, "", 0)
	Config(DEBUG)
}

// Check export
func Check() {
	fmt.Println("test")
}
