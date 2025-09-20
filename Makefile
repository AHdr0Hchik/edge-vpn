SHELL := /bin/bash

.PHONY: all bootstrap server gateway device ci

all: server gateway device

bootstrap:
	@echo "Install deps and build all"
	cd server && npm ci && npm run build
	cd gateway-agent && npm ci && npm run build
	cd device-agent && go build -o bin/device-agent

server:
	cd server && npm ci && npm run build

gateway:
	cd gateway-agent && npm ci && npm run build

device:
	cd device-agent && mkdir -p bin && go build -o bin/device-agent

ci:
	@echo "Run linters and builds"
	cd server && npm ci && npm run lint && npm run build
	cd gateway-agent && npm ci && npm run lint && npm run build
	cd device-agent && go vet ./... && go build -o bin/device-agent