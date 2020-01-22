###############################################
#
# Makefile
#
###############################################

.DEFAULT_GOAL := build

.PHONY: test

VERSION := 0.0.1

ver:
	@sed -i '' 's/^const Version = "[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}"/const Version = "${VERSION}"/' src/update/update.go

lint:
	$(shell go env GOPATH)/bin/golint ./src/...

fmt:
	go fmt ./src/...

vet:
	go vet ./src/...

build:
	go build -v ./src/...

clean:
	go clean ...

demo: build
	go run cmd/demo.go

test: build
	go test -v -count=${COUNT} ./src/...

github:
	open "https://github.com/mlavergn/goupdate"

release:
	zip -r goupdate.zip LICENSE README.md Makefile cmd src
	hub release create -m "${VERSION} - Go Update" -a goupdate.zip -t master "v${VERSION}"
	open "https://github.com/mlavergn/goupdate/releases"
