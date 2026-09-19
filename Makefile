BINARY := stigctl

.PHONY: build test tidy fmt vet

build:
	go build -o bin/$(BINARY) ./cmd/stigctl

test:
	go test ./...

tidy:
	go mod tidy

fmt:
	go fmt ./...

vet:
	go vet ./...
