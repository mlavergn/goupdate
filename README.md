[![Build Status](https://github.com/mlavergn/goupdate/workflows/CI/badge.svg?branch=master)](https://github.com/mlavergn/v/actions)
[![Go Report](https://goreportcard.com/badge/github.com/mlavergn/goupdate)](https://goreportcard.com/report/github.com/mlavergn/goupdate)
[![GoDoc](https://godoc.org/github.com/mlavergn/godaemon/src/daemon?status.svg)](https://godoc.org/github.com/mlavergn/godaemon/src/daemon)

# GoUpdate

Go Update is a single source file module which brings auto-update capabilities to Go applications.

## Implementation

GoUpdate automates checking for version updates from any source using the GitHub release JSON format.

The logic parses the JSON and looks for the "tag_name" to detemine the existance of a new version.

If an update is found, the module will look in the assets array for the first "browser_download_url"
JSON key that matches "Current Executable"-"Platform".zip (eg. demo-darwin.zip / demo-linux.zip)

The module will then download the binary using the URL in "browser_download_url" JSON key.

The module expects to download a zip file and finds the first file whos name matches the current
executable to use as the replacement executable.

The file is extracted, copied to the location of the currently running executable,

## Usage

Refering to the included demo, the application currently offers the following public APIs:

```golang
    import "github.com/mlavergn/goupdate/"

    currentVersion := "1.0.0"
    url : = "https://api.github.com/repos/mlavergn/godaemon/releases/latest"
    update := NewUpdate(url)
    // -or-
    // OAuth resource
    update := NewTokenUpdate(url, "A0B1C2D3E4F5A0B1C2D3E4F5A0B1C2D3E4F5")

    // one-time check (eg. on startup)
    release := update.Check(currentVersion)
    if release != nil {
        update.Update(release)
    }
    // -or-
    // auto-update
    intervalInMins := 24 * 60
    update.AutoUpdate(currentVersion, intervalInMins)
```
