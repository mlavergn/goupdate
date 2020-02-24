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
const Version = "0.5.5"

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
		} else {
			dlog = oslog.New(ioutil.Discard, "", 0)
		}
		return
	}

	log = oslog.New(os.Stderr, "", 0)
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
	Path  string
}

// NewSemanticVersion export
func NewSemanticVersion(version string) *SemanticVersion {
	ver := strings.ToUpper(version)
	ver = strings.TrimLeft(version, " ABCDEFGHIJKLMNOPQRSTUVWXYZ.")
	ver = strings.TrimRight(ver, " -ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	parts := strings.Split(ver, ".")
	if len(parts) < 3 {
		return nil
	}
	id := &SemanticVersion{
		Major: 0,
		Minor: 0,
		Patch: 0,
	}
	for i, part := range parts {
		value, _ := strconv.Atoi(part)
		switch i {
		case 0:
			id.Major = value
		case 1:
			id.Minor = value
		case 2:
			id.Patch = value
		}
	}
	if id.Major == 0 && id.Minor == 0 && id.Patch == 0 {
		return nil
	}

	// obtain the executable path
	fullPath, err := os.Executable()
	if err != nil {
		log.Println("NewSemanticVersion failed to obtain executable path", err)
		return nil
	}

	// resolve path if we're a symlink
	realPath, symErr := os.Readlink(fullPath)
	if symErr == nil {
		// will fall in here if we resolved a symlink
		fullPath = realPath
	}

	// split the executable path and filename
	basePath, fullName := filepath.Split(fullPath)
	id.Path = basePath

	if len(basePath) > 0 {
		cwdPath, err := os.Getwd()
		if err == nil && strings.HasPrefix(basePath, cwdPath) {
			basePath = "." + basePath[len(cwdPath):]
		}
		id.Path = basePath
	} else {
		id.Path = "./"
	}

	// trim any version tokens from the executable name
	shortName := fullName
	suffix := strings.LastIndex(fullName, "-")
	if suffix != -1 {
		shortName = shortName[:suffix]
	}

	// save the short name
	id.Name = shortName

	return id
}

// FullName export
func (id *SemanticVersion) FullName() string {
	return id.Name + "-" + strconv.Itoa(id.Major) + "." + strconv.Itoa(id.Minor) + "." + strconv.Itoa(id.Patch)
}

// PlatformArchiveName export
func (id *SemanticVersion) PlatformArchiveName() string {
	return id.Name + "-" + runtime.GOOS + "-" + runtime.GOARCH + ".zip"
}

// FullPath export
func (id *SemanticVersion) FullPath() string {
	return id.Path + id.FullName()
}

// SymlinkPath export
func (id *SemanticVersion) SymlinkPath() string {
	return id.Path + id.Name
}

// IsMoreRecentThan export
func (id *SemanticVersion) IsMoreRecentThan(version *SemanticVersion) bool {
	if id.Major > version.Major {
		return true
	}
	if id.Major == version.Major && id.Minor > version.Minor {
		return true
	}
	if id.Major == version.Major && id.Minor == version.Minor && id.Patch > version.Patch {
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
	Prerelease      bool          `json:"prerelease"`
	SemanticVersion SemanticVersion
}

// ----------------------------------------------------------------------------
// GoUpdate

// Update export
type Update struct {
	tlsConfigOnce sync.Once
	httpClient    *http.Client
	prerelease    bool
	githubURL     string
	authToken     string
}

// NewGitHubUpdate export
func NewGitHubUpdate(owner string, project string, token string, prerelease bool) *Update {
	id := &Update{
		prerelease: prerelease,
		githubURL:  "https://api.github.com/repos/" + owner + "/" + project + "/releases",
		authToken:  token,
	}
	return id
}

// NewGitHubEnterpriseUpdate export
func NewGitHubEnterpriseUpdate(host string, owner string, project string, token string, prerelease bool) *Update {
	id := &Update{
		prerelease: prerelease,
		githubURL:  "https://" + host + "/api/v3/repos/" + owner + "/" + project + "/releases",
		authToken:  token,
	}
	return id
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
		log.Println("Update.httpVersion NewRequest failed", reqErr)
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
		log.Println("Update.httpVersion Do failed", respErr)
		return nil
	}
	defer resp.Body.Close()

	// read the response body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Update.httpVersion read failed", err)
		return nil
	}

	// unmarshal the JSON response
	var release GitHubRelease
	err = json.Unmarshal(data, &release)
	if err != nil {
		log.Println("Update.httpVersion unmarshall failed", err)
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

	fileNameOS := release.SemanticVersion.PlatformArchiveName()
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
		log.Println("Update.httpDownload NewRequest failed", reqErr)
		return nil
	}
	req.Header.Set("Connection", "close")

	if len(id.authToken) > 0 {
		req.Header.Add("Authorization", "token "+id.authToken)
	}
	req.Header.Add("Accept", "application/octet-stream")

	resp, respErr := id.httpClient.Do(req)
	if respErr != nil {
		log.Println("Update.httpDownload Do failed", respErr)
		return nil
	}

	reader := bufio.NewReader(resp.Body)
	defer resp.Body.Close()

	file, tempErr := ioutil.TempFile("", release.SemanticVersion.Name)
	if tempErr != nil {
		log.Println("Update.httpDownload TempFile failed", tempErr)
		return nil
	}
	log.Println("Update.httpDownload downloading to", file.Name())
	io.Copy(file, reader)

	return file
}

// Check obtains the latest release version from GitHub
func (id *Update) Check(currentVer *SemanticVersion) *GitHubRelease {
	dlog.Println("Update.Check")

	release := id.httpVersion()
	if release == nil {
		log.Println("Update.Check failed to obtain release info")
		return nil
	}

	// check if latests is prerelease and if so, do we accept prereleases
	if release.Prerelease && !id.prerelease {
		log.Println("Update.Check latest is prerelease but prerelease not enabled")
		return nil
	}

	releaseVer := NewSemanticVersion(release.Version)
	if releaseVer == nil {
		log.Println("Update.Check failed to generate semantic version for", release)
		return nil
	}
	release.SemanticVersion = *releaseVer

	if releaseVer.IsMoreRecentThan(currentVer) {
		return release
	}

	return nil
}

// Update obtains the latest release binary from GitHub and writes it to disk
func (id *Update) Update(current *SemanticVersion, release *GitHubRelease) bool {
	dlog.Println("Update.Update", current)

	file := id.httpDownload(release)
	defer file.Close()

	if file == nil {
		log.Println("Update.Update failed to locate platform binary")
		return false
	}

	// unzip the packed data
	stat, _ := file.Stat()
	zipReader, zipErr := zip.NewReader(file, stat.Size())
	if zipErr != nil {
		log.Println("Update.Update failed to unzip packed data", zipErr)
		return false
	}

	// assumption:
	// - name in archive will be non-versioned (eg. demo, not demo-1.0.0)
	shortName := release.SemanticVersion.Name
	var zipFile *zip.File
	for _, zipEntry := range zipReader.File {
		if strings.HasSuffix(zipEntry.Name, shortName) {
			zipFile = zipEntry
			break
		}
	}
	if zipFile == nil {
		log.Println("Update.Update failed to find executable in archive", shortName)
		return false
	}

	// open the zip file for reading
	src, srcErr := zipFile.Open()
	if srcErr != nil {
		log.Println("Update.Update failed to open", srcErr)
		return false
	}

	// open the disk file for writing
	updateFullPath := release.SemanticVersion.FullPath()
	dest, destErr := os.Create(updateFullPath)
	if destErr != nil {
		log.Println("Update.Update failed to extract", destErr)
		src.Close()
		return false
	}

	// pipe zip to disk
	dlog.Println("Write executable file", updateFullPath)
	io.Copy(dest, src)
	dest.Sync()

	// close src
	src.Close()

	// make file executable
	dlog.Println("Update.Update set executable flag", updateFullPath)
	chmodErr := dest.Chmod(0755)
	if chmodErr != nil {
		log.Println("Update.Update failed to chmod executable", chmodErr)
		dest.Close()
		return false
	}

	// close dest
	dest.Close()

	// recreate symlink if it exists
	symlinkPath := current.SymlinkPath()
	stat, err := os.Lstat(symlinkPath)
	if err == nil && stat.Mode()&os.ModeSymlink != 0 {
		dlog.Println("Update.Update recreate symlink", shortName, updateFullPath)
		remErr := os.Remove(symlinkPath)
		if remErr != nil {
			log.Println("Update.Update failed to remove symlink", remErr)
		}
		symErr := os.Symlink(release.SemanticVersion.FullPath(), symlinkPath)
		if symErr != nil {
			log.Println("Update.Update failed to create symlink", symErr)
		}
	}

	return true
}

// RemoveVersion export
func (id *Update) RemoveVersion(version *SemanticVersion) {
	// remove old file
	cwdFiles, cwdErr := ioutil.ReadDir(".")
	if cwdErr == nil {
		for _, cwdFile := range cwdFiles {
			if cwdFile.Name() == version.FullName() {
				dlog.Println("Update.RemoveVersion removing", cwdFile.Name())
				os.Remove(cwdFile.Name())
				break
			}
		}
	}
}

// AutoUpdate export
func (id *Update) AutoUpdate(current *SemanticVersion, interval time.Duration, restartFunc func(release *SemanticVersion)) {
	log.Println("Update.AutoUpdate", *current, interval)
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				log.Println("auto-update update check for", current.FullName())
				release := id.Check(current)
				if release != nil {
					log.Println("auto-update new version available", release.SemanticVersion.FullName())
					if !id.Update(current, release) {
						log.Println("auto-update new version installation failed, aborting")
						return
					}
					log.Println("auto-update new version installed", release.SemanticVersion.FullPath())
					if restartFunc != nil {
						ticker.Stop()
						restartFunc(&release.SemanticVersion)
					}
				}
			}
		}
	}()
}
