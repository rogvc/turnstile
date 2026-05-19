BINARY  := turnstile
MODULE  := github.com/rogvc/turnstile
VERSION ?= dev
LDFLAGS := -ldflags "-s -w -X $(MODULE)/cmd/version.version=$(VERSION)"

.PHONY: build test lint install run clean template

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
