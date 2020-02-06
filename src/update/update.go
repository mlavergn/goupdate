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
const Version = "0.3.2"

// DEBUG flag
const DEBUG = false

// stand-in for system logger
var log *oslog.Logger

// debug logger
var dlog *oslog.Logger

// Config export
func Config(debug bool, logger *oslog.Logger) {
	if logger != nil {
		log = logger
		if debug {
			dlog = logger
		}
		return
	}

	log = oslog.New(os.Stderr, "GoUpdate ", oslog.Ltime|oslog.Lshortfile)
	if debug {
		dlog = oslog.New(os.Stdout, "GoUpdate ", oslog.Ltime|oslog.Lshortfile)
	} else {
		dlog = oslog.New(ioutil.Discard, "", 0)
	}
}

func init() {
	Config(DEBUG, nil)
}

// ----------------------------------------------------------------------------
// Sematic versioning

// SemanticVersion export
type SemanticVersion struct {
	Name  string
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

	// isoalte the executable name
	execName, err := os.Executable()
	if err != nil {
		log.Println(err)
		return nil
	}
	_, execFile := filepath.Split(execName)
	result.Name = execFile

	return result
}

// QualifiedName export
func (id *SemanticVersion) QualifiedName() string {
	return id.Name + "-" + strconv.Itoa(id.Major) + "." + strconv.Itoa(id.Minor) + "." + strconv.Itoa(id.Patch)
}

// PlatformArchive export
func (id *SemanticVersion) PlatformArchive() string {
	return id.Name + "-" + runtime.GOOS + "-" + runtime.GOARCH + ".zip"
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
	Version         string        `json:"tag_name"`
	Assets          []GitHubAsset `json:"assets"`
	SemanticVersion SemanticVersion
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
	dlog.Println("Update.initTLS")
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
	dlog.Println("Update.httpVersion")
	id.initTLS()

	// generate the request
	urlString := id.githubURL + "/latest"
	req, reqErr := http.NewRequest(http.MethodGet, urlString, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}
	req.Header.Set("Connection", "close")

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

	release.SemanticVersion = *NewSemanticVersion(release.Version)

	return &release
}

// httpDownload parses  the release JSON for the latest release of
// of the owner:project provided at initialization
func (id *Update) httpDownload(release *GitHubRelease) *os.File {
	dlog.Println("Update.httpDownload")
	id.initTLS()

	assetID := -1

	fileNameOS := release.SemanticVersion.PlatformArchive()
	for _, asset := range release.Assets {
		if asset.Name == fileNameOS {
			assetID = asset.ID
			break
		}
	}

	if assetID == -1 {
		log.Println("Update.httpDownload failed to locate platform specific asset", fileNameOS)
		return nil
	}

	urlString := id.githubURL + "/assets/" + strconv.Itoa(assetID)
	log.Println("Update.httpDownload url", urlString)

	req, reqErr := http.NewRequest(http.MethodGet, urlString, nil)
	if reqErr != nil {
		log.Println(reqErr)
		return nil
	}
	req.Header.Set("Connection", "close")

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

	file, tempErr := ioutil.TempFile("", release.SemanticVersion.Name)
	log.Println("Update.httpDownload downloading to", file.Name())
	if tempErr != nil {
		log.Println(tempErr)
		return nil
	}
	io.Copy(file, reader)

	return file
}

// Check obtains the latest release version from GitHub
func (id *Update) Check(currentVer SemanticVersion) *GitHubRelease {
	dlog.Println("Update.Check")

	release := id.httpVersion()
	if release == nil {
		log.Println("Failed to obtain release info")
		return nil
	}
	releaseVer := NewSemanticVersion(release.Version)
	if releaseVer == nil {
		log.Println("Failed to generate semantic version for", release)
		return nil
	}
	release.SemanticVersion = *releaseVer

	if currentVer.IsLessThan(releaseVer) {
		log.Println("Update available", release.Version)
		return release
	}

	log.Println("No update available")
	return nil
}

// Update obtains the latest release binary from GitHub and writes it to disk
func (id *Update) Update(release *GitHubRelease) bool {
	dlog.Println("Update.Update")

	file := id.httpDownload(release)
	defer file.Close()

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

	fileName := release.SemanticVersion.Name
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

	// write update to disk
	fileNameVer := release.SemanticVersion.QualifiedName()
	src, _ := zipFile.Open()
	defer src.Close()
	dest, destErr := os.Create(fileNameVer)
	if destErr != nil {
		log.Println("Failed to extract", destErr)
		return false
	}
	dlog.Println("Write executable file", fileNameVer)
	io.Copy(dest, src)

	// make file executable
	dlog.Println("Set executable flag", fileNameVer)
	chmodErr := dest.Chmod(0755)
	if chmodErr != nil {
		log.Println("Failed to chmod executabke", chmodErr)
		return false
	}

	// recreate symlink
	dlog.Println("Recreate symlink", fileName, fileNameVer)
	log.Println(fileName, fileNameVer)
	os.Remove(fileName)
	os.Symlink(fileNameVer, fileName)

	return true
}

// RemoveVersion export
func (id *Update) RemoveVersion(version SemanticVersion) {
	// remove old file
	dir, wdErr := os.Getwd()
	if wdErr == nil {
		cwdFiles, cwdErr := ioutil.ReadDir(".")
		if cwdErr == nil {
			for _, cwdFile := range cwdFiles {
				if cwdFile.Name() == version.QualifiedName() {
					dlog.Println("Removing", cwdFile.Name())
					os.Remove(cwdFile.Name())
				}
			}
		}
	}
}

// AutoUpdate export
func (id *Update) AutoUpdate(version SemanticVersion, interval time.Duration, fn func(string)) {
	dlog.Println("Update.AutoUpdate", version, interval)

	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				release := id.Check(version)
				if release != nil {
					ticker.Stop()
					id.Update(release)
					if fn != nil {
						fn(release.Version)
					}
				}
			}
		}
	}()
}
