MODULE     := github.com/Dyneteq/Breach-Harbor
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE       := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) \
           -X $(MODULE)/internal/version.Commit=$(COMMIT) \
           -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test vet fmt fmt-check clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/breachharbor ./cmd/breachharbor
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/bh ./cmd/bh

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:" && gofmt -l . && exit 1)

clean:
	rm -rf bin/
