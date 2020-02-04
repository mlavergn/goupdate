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
	"runtime"
	"strings"
	"sync"
	"time"
)

// Version export
const Version = "0.1.0"

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

// Update export
type Update struct {
	releaseURL string
	token      string
}

// NewUpdate export
func NewUpdate(releaseURL string) *Update {
	return &Update{
		releaseURL: releaseURL,
	}
}

// NewTokenUpdate export
func NewTokenUpdate(releaseURL string, token string) *Update {
	return &Update{
		releaseURL: releaseURL,
		token:      token,
	}
}

var tlsConfigOnce sync.Once
var httpClient *http.Client

func (id *Update) initTLS() {
	log.Println("Update.initTLS")
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

func (id *Update) httpVersion(url string) *Release {
	log.Println("Update.httpVersion")
	id.initTLS()

	req, reqErr := http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}

	if len(id.token) > 0 {
		req.Header.Add("Authorization", "token "+id.token)
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

func (id *Update) httpDownload(release Release, fileName string) *os.File {
	log.Println("Update.httpDownload")
	id.initTLS()

	req, reqErr := http.NewRequest(http.MethodGet, release.Assets[0].Download, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}

	if len(id.token) > 0 {
		req.Header.Add("Authorization", "token "+id.token)
	}

	resp, respErr := httpClient.Do(req)
	if respErr != nil {
		log.Println(respErr)
		return nil
	}

	reader := bufio.NewReader(resp.Body)
	defer resp.Body.Close()

	file, tempErr := ioutil.TempFile("", fileName)
	log.Println("Update.httpDownload downloading to", file.Name())
	if tempErr != nil {
		log.Println(tempErr)
		return nil
	}
	io.Copy(file, reader)

	return file
}

func executableFile() string {
	execName, err := os.Executable()
	if err != nil {
		log.Println(err)
		return ""
	}
	_, execFile := filepath.Split(execName)
	return execFile
}

// check latest version from source of truth
func (id *Update) checkHandler(current string) *Release {
	log.Println("Update.checkHandler")

	release := id.httpVersion(id.releaseURL)
	if release != nil && len(release.Version) > 0 && release.Version > current {
		return release
	}

	return nil
}

// download latest version from source of truth
func (id *Update) updateHandler(release *Release) bool {
	log.Println("Update.updateHandler")

	file := id.httpDownload(*release, executableFile()+"-"+release.Version+".zip")

	// unzip the packed data
	stat, _ := file.Stat()
	zipReader, zipErr := zip.NewReader(file, stat.Size())
	if zipErr != nil {
		log.Println("Failed to unzip packed data", zipErr)
		return false
	}

	fileName := executableFile()
	fileNameVer := executableFile() + "-" + release.Version
	fileNameOS := executableFile() + "-" + runtime.GOOS + "-" + runtime.GOARCH
	log.Println("Update.updateHandler", fileName, fileNameVer, fileNameOS)
	var zipFile *zip.File
	for _, zipEntry := range zipReader.File {
		if strings.HasSuffix(zipEntry.Name, fileNameOS) {
			break
		}
	}
	if zipFile == nil {
		log.Println("Failed to find executable in download bundle", fileName)
		return false
	}
	src, _ := zipFile.Open()
	defer src.Close()
	dest, destErr := os.Create(fileNameVer)
	if destErr != nil {
		log.Println("Failed to extract", destErr)
		return false
	}
	io.Copy(dest, src)

	// recreate symlink
	os.Remove(fileName)
	os.Symlink(fileName, fileNameVer)

	return true
}

// AutoUpdate export
func (id *Update) AutoUpdate(version string, intervalMin int) {
	log.Println("Update.AutoUpdate", version, intervalMin)

	ticker := time.NewTicker(500 * time.Minute)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				release := id.checkHandler(version)
				if release != nil {
					ticker.Stop()
					id.updateHandler(release)
				}
			}
		}
	}()
}

// Update export
func (id *Update) Update(release *Release) bool {
	log.Println("Update.Update", release.Version)

	return id.updateHandler(release)
}

// Check export
func (id *Update) Check(version string) *Release {
	log.Println("Update.Check", version)

	release := id.checkHandler(version)
	if release != nil {
		log.Println("Update available", version, release.Assets)
	} else {
		log.Println("No update available")
	}
	return release
}
