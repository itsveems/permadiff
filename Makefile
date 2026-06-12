VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet demo clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/permadiff ./cmd/permadiff

test:
	go vet ./...
	go test ./...

demo: build
	./bin/permadiff examples/demo-plan.json

clean:
	rm -rf bin
