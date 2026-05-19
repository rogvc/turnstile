BINARY  := turnstile
MODULE  := github.com/rogvc/turnstile
VERSION ?= dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
ifdef RELEASE
	LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
endif

.PHONY: build test lint install run clean fmt vet tidy ci

build:
	go build $(LDFLAGS) -o bin/$(BINARY) .

test:
	go test -race ./...

lint:
	golangci-lint run

install:
	go install $(LDFLAGS) .

run:
	go run . $(ARGS)

clean:
	rm -rf bin/

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

ci: build vet test lint
