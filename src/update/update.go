package update

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	oslog "log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Version export
const Version = "0.0.1"

// DEBUG flag for runtime
const DEBUG = true

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

func httpVersion(url string) string {
	if DEBUG {
		return "1.0.0"
	}

	httpTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}

	httpClient := &http.Client{
		Transport: httpTransport,
	}

	req, reqErr := http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return ""
	}
	resp, respErr := httpClient.Do(req)
	if respErr != nil {
		log.Println(respErr)
		return ""
	}

	reader := bufio.NewReader(resp.Body)
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Println(err)
		return ""
	}

	return string(data)
}

func httpDownload(url string, bundle string) *os.File {
	if true {
		return nil
	}

	httpTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}

	httpClient := &http.Client{
		Transport: httpTransport,
	}

	req, reqErr := http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}
	resp, respErr := httpClient.Do(req)
	if respErr != nil {
		log.Println(respErr)
		return nil
	}

	reader := bufio.NewReader(resp.Body)
	defer resp.Body.Close()

	file, tempErr := ioutil.TempFile("", bundle)
	if tempErr != nil {
		log.Println(tempErr)
		return nil
	}
	io.Copy(file, reader)

	return file
}

// pull version from source of truth
func update(current string) string {
	url := "http://localhost/name/releases/current"
	ver := httpVersion(url)
	if len(ver) > 0 && ver > current {
		return ver
	}
	return ""
}

// download updated version
func download(file string, version string) *os.File {
	bundle := file + "-" + version
	url := "http://localhost/name/releases/" + bundle
	tmp := httpDownload(url, file+"-"+version)
	return tmp
}

// copy from tmp to working dir
func install(file *os.File) {
	os.Rename(file.Name(), "workingDir"+"name-1.0.0")
}

// restart the service
func restart() {
	// exec.Command
}

// Check export
func Check(current string) {
	fmt.Println("Update complete")

	execName, err := os.Executable()
	if err != nil {
		fmt.Println(err)
		return
	}
	_, execFile := filepath.Split(execName)

	fmt.Println(execFile)

	if ver := update(current); len(ver) > 0 {
		file := download(execFile, ver)
		if file != nil {
			install(file)
			restart()
		}
	}

	fmt.Println("Update check complete")
}
