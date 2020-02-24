###############################################
#
# Makefile
#
###############################################

.DEFAULT_GOAL := build

.PHONY: test

VERSION := 0.6.0

ver:
	@sed -i '' 's/^const Version = "[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}"/const Version = "${VERSION}"/' update.go

lint:
	$(shell go env GOPATH)/bin/golint ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

build:
	go build -v ./...

clean:
	go clean ...

demo: build
	go build -o demo cmd/demo.go

test: build
	go test -v -count=1 ./...

github:
	open "https://github.com/mlavergn/goupdate"

package:
	GOARCH=amd64 GOOS=linux go build -o demo cmd/demo.go
	zip -r demo-linux-amd64.zip LICENSE README.md demo
	GOARCH=arm GOARM=5 GOOS=linux go build -o demo cmd/demo.go
	zip -r demo-linux-arm.zip LICENSE README.md demo
	GOARCH=amd64 GOOS=darwin go build -o demo cmd/demo.go
	zip -r demo-darwin-amd64.zip LICENSE README.md demo
	hub release edit -m "" -a demo-linux-amd64.zip -a demo-darwin-amd64.zip -a demo-linux-arm.zip v${VERSION}
	open "https://github.com/mlavergn/goupdate/releases"

release:
	zip -r goupdate.zip LICENSE README.md Makefile cmd *.go go.mod
	hub release create -m "${VERSION} - Go Update" -a goupdate.zip -t master "v${VERSION}"
	open "https://github.com/mlavergn/goupdate/releases"
