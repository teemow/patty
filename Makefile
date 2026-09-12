.DEFAULT_GOAL := help

VERSION ?= $(shell ./scripts/get-latest-version.sh 2>/dev/null || echo dev)

.PHONY: build
build: ## Build the binary
	@go build -ldflags "-X main.version=$(VERSION)" -o patty .

.PHONY: install
install: ## Install locally
	@go install -ldflags "-X main.version=$(VERSION)" .

.PHONY: test
test: ## Run tests
	@go test -race ./...

.PHONY: lint
lint: ## Run linter
	@golangci-lint run

.PHONY: logo
logo: ## Render the logo PNGs from assets/logo.svg
	@rsvg-convert -h 640 assets/logo.svg -o assets/logo-light.png
	@rsvg-convert -h 640 assets/logo-dark.svg -o assets/logo-dark.png

.PHONY: release-dry-run
release-dry-run: ## Test the release process without publishing
	@goreleaser release --snapshot --clean --skip=announce,publish,validate

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
