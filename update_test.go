package update

import (
	"runtime"
	"strings"
	"testing"
)

func TestSemanticVersionFullPath(t *testing.T) {
	version := NewSemanticVersion("1.0.0")
	actual := version.FullPath()
	expect := "/goupdate.test-1.0.0"
	if !strings.HasSuffix(actual, expect) {
		t.Fatal("FullPath unexpected result", actual, expect)
	}
}

func TestSemanticVersionPlatformArchiveName(t *testing.T) {
	version := NewSemanticVersion("1.0.0")
	actual := version.PlatformArchiveName()
	expect := "goupdate.test-" + runtime.GOOS + "-" + runtime.GOARCH + ".zip"
	if actual != expect {
		t.Fatal("PlatformArchiveName unexpected result", actual, expect)
	}
}

func TestSemanticVersionIsMoreRecentThan(t *testing.T) {
	versionA := NewSemanticVersion("1.0.1")
	versionB := NewSemanticVersion("1.0.10")
	actual := versionB.IsMoreRecentThan(versionA)
	expect := true
	if actual != expect {
		t.Fatal("IsMoreRecentThan unexpected result", actual, expect)
	}
}
