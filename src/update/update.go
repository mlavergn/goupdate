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

// ----------------------------------------------------------------------------
// init

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

// ----------------------------------------------------------------------------
// Sematic versioning

// SemanticVersion export
type SemanticVersion struct {
	Major int
	Minor int
	Patch int
}

// NewSemanticVersion export
func NewSemanticVersion(version string) *SemanticVersion {
	ver := strings.TrimLeft(version, " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.")
	ver = strings.TrimRight(ver, " -abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	parts := strings.Split(ver, ".")
	if len(parts) < 3 {
		return nil
	}
	result := &SemanticVersion{
		Major: 0,
		Minor: 0,
		Patch: 0,
	}
	for i, part := range parts {
		value, _ := strconv.Atoi(part)
		switch i {
		case 0:
			result.Major = value
		case 1:
			result.Minor = value
		case 2:
			result.Patch = value
		}
	}
	if result.Major == 0 && result.Minor == 0 && result.Patch == 0 {
		return nil
	}
	return result
}

// IsLessThan export
func (id *SemanticVersion) IsLessThan(version *SemanticVersion) bool {
	if id.Major < version.Major {
		return true
	}
	if id.Major == version.Major && id.Minor < version.Minor {
		return true
	}
	if id.Major == version.Major && id.Minor == version.Minor && id.Patch < version.Patch {
		return true
	}
	return false
}

// ----------------------------------------------------------------------------
// GitHub types

// GitHubAsset export
type GitHubAsset struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Download string `json:"browser_download_url"`
}

// GitHubRelease export
type GitHubRelease struct {
	Version string        `json:"tag_name"`
	Assets  []GitHubAsset `json:"assets"`
}

// ----------------------------------------------------------------------------
// GoUpdate

// Update export
type Update struct {
	tlsConfigOnce sync.Once
	httpClient    *http.Client

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

// TLS intialization is expensive and can be reused safely
func (id *Update) initTLS() {
	log.Println("Update.initTLS")
	id.tlsConfigOnce.Do(func() {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		// based on UNIX CA file location
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

		id.httpClient = &http.Client{
			Transport: httpTransport,
		}
	})
}

// httpVersion reads the release JSON for the latest release of
// of the owner:project provided at initialization
func (id *Update) httpVersion() *GitHubRelease {
	log.Println("Update.httpVersion")
	id.initTLS()

	// generate the request
	urlString := id.githubURL + "/latest"
	req, reqErr := http.NewRequest(http.MethodGet, urlString, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}

	// generate the request
	if len(id.authToken) > 0 {
		req.Header.Add("Authorization", "token "+id.authToken)
	}

	// perform the request
	resp, respErr := id.httpClient.Do(req)
	if respErr != nil {
		log.Println(respErr)
		return nil
	}
	defer resp.Body.Close()

	// read the response body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return nil
	}

	// unmarshal the JSON response
	var release GitHubRelease
	err = json.Unmarshal(data, &release)
	if err != nil {
		log.Println(err)
		return nil
	}

	return &release
}

// httpDownload parses  the release JSON for the latest release of
// of the owner:project provided at initialization
func (id *Update) httpDownload(release *GitHubRelease, fileName string) *os.File {
	log.Println("Update.httpDownload")
	id.initTLS()

	assetID := -1

	fileNameOS := fileName + "-" + runtime.GOOS + "-" + runtime.GOARCH + ".zip"
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

	resp, respErr := id.httpClient.Do(req)
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

func (id *Update) executableFile() string {
	execName, err := os.Executable()
	if err != nil {
		log.Println(err)
		return ""
	}
	_, execFile := filepath.Split(execName)
	return execFile
}

// Check obtains the latest release version from GitHub
func (id *Update) Check(current string) *GitHubRelease {
	log.Println("Update.checkHandler")

	currentVer := NewSemanticVersion(current)
	if currentVer == nil {
		log.Println("Failed to generate semantic version for", current)
		return nil
	}
	release := id.httpVersion()
	if release == nil {
		log.Println("Failed to obtain release info")
		return nil
	}
	releaseVer := NewSemanticVersion(release.Version)
	if releaseVer == nil {
		log.Println("Failed to generate semantic version for", current)
		return nil
	}

	log.Println(currentVer, releaseVer)

	if currentVer.IsLessThan(releaseVer) {
		log.Println("Update available", release.Version)
		return release
	} else {
		log.Println(current, "is the latest version available")
	}

	return nil
}

// Update obtains the latest release binary from GitHub and writes it to disk
func (id *Update) Update(release *GitHubRelease) bool {
	log.Println("Update.updateHandler")

	fileName := id.executableFile()
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
				release := id.Check(version)
				if release != nil {
					ticker.Stop()
					id.Update(release)
				}
			}
		}
	}()
}
