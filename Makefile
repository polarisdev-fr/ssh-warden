.PHONY: build build-server build-cli build-helper clean

build: build-server build-cli build-helper

build-server:
	go build -o bin/ssh-warden-server ./cmd/server

build-cli:
	go build -o bin/ssh-warden ./cmd/cli

build-helper:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/ssh-warden-helper ./cmd/helper

clean:
	rm -rf bin/