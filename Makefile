# Project directories
ROOT_DIR        := $(CURDIR)
BUILD_DIR       := $(ROOT_DIR)/build

# Ensure everything works even if GOPATH is not set, which is often the case.
GOPATH          ?= $(shell go env GOPATH)

# Set $(GOBIN) to project directory for keeping everything in one place
GOBIN            = $(ROOT_DIR)/bin

# All go files belong to project
GOFILES          = $(shell find . -type f -name '*.go' -not -path './vendor/*')

# Commands used in Makefile
GOCMD           := GOBIN=$(GOBIN) go
GOBUILD         := $(GOCMD) build
GOTEST          := $(GOCMD) test
GOMOD           := $(GOCMD) mod
GOINSTALL       := $(GOCMD) install
GOCLEAN         := $(GOCMD) clean
GOFMT           := gofmt

GOLANGCILINT    := $(GOBIN)/golangci-lint

MODULE          := $(shell $(GOCMD) list -m)
COMMIT          := $(strip $(shell [ -d .git ] && git describe --always --tags --dirty))
BUILD_TIMESTAMP := $(shell date -u +"%Y-%m-%dT%H:%M:%S%Z")

# Build variables
BUILD_LDFLAGS   := '-s -w -extldflags -static'

# Helper variables
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

default: help

.PHONY: vault-init
vault-init: ## Builds vault-init binary
vault-init: vendor main.go $(wildcard *.go) $(wildcard */*.go) $(BUILD_DIR) ; $(info $(M) building binary)
	$(Q) CGO_ENABLED=0 $(GOBUILD) -a -tags netgo -trimpath -ldflags $(BUILD_LDFLAGS) -o $(BUILD_DIR)/$@ main.go

.PHONY: vendor
vendor: ## Updates vendored copy of dependencies
vendor: ; $(info $(M) running go mod vendor)
	$(Q) $(GOMOD) tidy
	$(Q) $(GOMOD) vendor

.PHONY: fix
fix: ## Fix found issues (if it's supported by the $(GOLANGCILINT))
fix: install-tools ; $(info $(M) runing golangci-lint run --fix)
	$(Q) $(GOLANGCILINT) run --fix --enable-all -c .golangci.yml

.PHONY: fmt
fmt: ## Runs gofmt
fmt: ; $(info $(M) runnig gofmt )
	$(Q) $(GOFMT) -d -s $(GOFILES)

.PHONY: lint
lint: ## Runs golangci-lint analysis
lint: install-tools vendor fmt ; $(info $(M) runnig golangci-lint analysis)
	$(Q) $(GOLANGCILINT) run

.PHONY: clean
clean: ## Cleanup everything
clean: ; $(info $(M) cleaning )
	$(Q) $(GOCLEAN)
	$(Q) $(shell rm -rf $(GOBIN) $(BUILD_DIR))

.PHONY: test
test: ## Runs go test
test: ; $(info $(M) runnig tests)
	$(Q) $(GOTEST) -race -cover -v ./...

.PHONY: install-tools
install-tools: ## Install tools
install-tools: vendor ; $(info $(M) installing tools)
	$(Q) $(GOINSTALL) $(shell cat tools.go | grep _ | awk -F'"' '{print $$2}')

.PHONY: help
help: ## shows this help message
	$(Q) awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m\t %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

$(BUILD_DIR): ; $(info $(M) creating build directory)
	$(Q) $(shell mkdir -p $@)