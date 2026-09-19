BINARY := stigctl
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w 	-X github.com/Exonical/stigctl/internal/version.Version=$(VERSION) 	-X github.com/Exonical/stigctl/internal/version.Commit=$(COMMIT) 	-X github.com/Exonical/stigctl/internal/version.Date=$(DATE)

.PHONY: build test tidy fmt vet clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/stigctl

test:
	go test ./...

tidy:
	go mod tidy

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

vet:
	go vet ./...

clean:
	rm -rf bin
