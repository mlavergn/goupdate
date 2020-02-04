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
	"strconv"
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
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Download string `json:"browser_download_url"`
}

// Release export
type Release struct {
	Version string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Update export
type Update struct {
	githubURL string
	authToken string
}

// NewGitHubUpdate export
func NewGitHubUpdate(owner string, project string, token string) *Update {
	return &Update{
		authToken: token,
		githubURL: "https://api.github.com/repos/" + owner + "/" + project + "/releases",
	}
}

// NewGitHubEnterpriseUpdate export
func NewGitHubEnterpriseUpdate(host string, owner string, project string, token string) *Update {
	return &Update{
		authToken: token,
		githubURL: "https://" + host + "/api/v3/repos/" + owner + "/" + project + "/releases",
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

func (id *Update) httpVersion() *Release {
	log.Println("Update.httpVersion")
	id.initTLS()

	urlString := id.githubURL + "/latest"
	log.Println("Update.httpVersion url", urlString)

	req, reqErr := http.NewRequest(http.MethodGet, urlString, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}

	if len(id.authToken) > 0 {
		req.Header.Add("Authorization", "token "+id.authToken)
	}

	resp, respErr := httpClient.Do(req)
	if respErr != nil {
		log.Println(respErr)
		return nil
	}

	// reader := bufio.NewReader(resp.Body)
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
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

func (id *Update) httpDownload(release *Release, fileName string) *os.File {
	log.Println("Update.httpDownload")
	id.initTLS()

	assetID := -1

	// fileNameOS := fileName + "-" + runtime.GOOS + "-" + runtime.GOARCH
	fileNameOS := fileName + "-" + "linux" + "-" + runtime.GOARCH + ".zip"
	for _, asset := range release.Assets {
		if asset.Name == fileNameOS {
			assetID = asset.ID
			break
		}
	}

	if assetID == -1 {
		log.Println("Update.httpDownload filed to locate platform specific asset", fileNameOS)
		return nil
	}

	urlString := id.githubURL + "/assets/" + strconv.Itoa(assetID)
	log.Println("Update.httpDownload url", urlString)

	req, reqErr := http.NewRequest(http.MethodGet, urlString, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}

	if len(id.authToken) > 0 {
		req.Header.Add("Authorization", "token "+id.authToken)
	}
	req.Header.Add("Accept", "application/octet-stream")

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

	release := id.httpVersion()
	if release != nil && len(release.Version) > 0 && release.Version > current {
		return release
	}

	return nil
}

// download latest version from source of truth
func (id *Update) updateHandler(release *Release) bool {
	log.Println("Update.updateHandler")

	fileName := executableFile()
	file := id.httpDownload(release, fileName)

	if file == nil {
		log.Println("Failed to locate platform binary")
		return false
	}

	// unzip the packed data
	stat, _ := file.Stat()
	zipReader, zipErr := zip.NewReader(file, stat.Size())
	if zipErr != nil {
		log.Println("Failed to unzip packed data", zipErr)
		return false
	}

	var zipFile *zip.File
	for _, zipEntry := range zipReader.File {
		if strings.HasSuffix(zipEntry.Name, fileName) {
			zipFile = zipEntry
			break
		}
	}
	if zipFile == nil {
		log.Println("Failed to find executable in download bundle", fileName)
		return false
	}

	fileNameVer := fileName + "-" + release.Version
	src, _ := zipFile.Open()
	defer src.Close()
	dest, destErr := os.Create(fileNameVer)
	if destErr != nil {
		log.Println("Failed to extract", destErr)
		return false
	}
	io.Copy(dest, src)

	// recreate symlink
	log.Println(fileName, fileNameVer)
	os.Remove(fileName)
	os.Symlink(fileNameVer, fileName)

	return true
}

// Public APIs

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
		log.Println("Update available", release.Version)
	} else {
		log.Println("No update available")
	}
	return release
}
