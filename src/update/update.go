package update

import (
	"archive/zip"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	oslog "log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
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

// Asset export
type Asset struct {
	Download string `json:"browser_download_url"`
}

// Release export
type Release struct {
	Version string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// GoUpdate export
type GoUpdate struct {
	releaseURL string
}

// NewGoUpdate export
func NewGoUpdate(releaseURL string) *GoUpdate {
	return &GoUpdate{
		releaseURL: releaseURL,
	}
}

var tlsConfigOnce sync.Once

// var tlsConfig *tls.Config
var httpClient *http.Client

func initTLS() {
	log.Println("GoUpdate.initTLS")
	tlsConfigOnce.Do(func() {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		// currently based on Linux CA location
		caCert, err := ioutil.ReadFile("/etc/ssl/ca-bundle.crt")
		if err == nil {
			rootCAs.AppendCertsFromPEM(caCert)
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			RootCAs:            rootCAs,
		}

		httpTransport := &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
		}

		httpClient = &http.Client{
			Transport: httpTransport,
		}
	})
}

func httpVersion(url string) *Release {
	log.Println("GoUpdate.httpVersion")
	initTLS()

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

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Println(err)
		return nil
	}

	var release Release
	err = json.Unmarshal(data, &release)
	if err != nil {
		log.Println(err)
		return nil
	}

	return &release
}

func httpDownload(release Release, fileName string) *os.File {
	log.Println("GoUpdate.httpDownload")
	initTLS()

	req, reqErr := http.NewRequest(http.MethodGet, release.Assets[0].Download, nil)
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

	file, tempErr := ioutil.TempFile("", fileName)
	if tempErr != nil {
		log.Println(tempErr)
		return nil
	}
	io.Copy(file, reader)

	return file
}

func latestFile(version string) string {
	execName, err := os.Executable()
	if err != nil {
		log.Println(err)
		return ""
	}
	_, execFile := filepath.Split(execName)
	return execFile + "-" + version
}

// pull version from source of truth
func (id *GoUpdate) update(current string) bool {
	log.Println("GoUpdate.update")

	release := httpVersion(id.releaseURL)
	if release != nil && len(release.Version) > 0 && release.Version > current {
		file := httpDownload(*release, latestFile(current)+".zip")

		// unzip the packed data
		stat, _ := file.Stat()
		zipReader, zipErr := zip.NewReader(file, stat.Size())
		if zipErr != nil {
			log.Println("Failed to unzip packed data", zipErr)
			return false
		}

		zipFile := zipReader.File[0]
		src, _ := zipFile.Open()
		defer src.Close()
		dest, destErr := os.Create(latestFile(current))
		if destErr != nil {
			log.Println("Failed to extract", destErr)
			return false
		}
		io.Copy(dest, src)

		return true
	}

	return false
}

// Check export
func (id *GoUpdate) Check(version string) {
	log.Println("GoUpdate.Check", version)

	updated := id.update(version)

	if updated {
		log.Println("Update available")
	} else {
		log.Println("No update available")
	}
}
