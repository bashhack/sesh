# Check for .env file and include it
ifneq (,$(wildcard .env))
	include .env
	export
endif

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date +%FT%T%z)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

PREFIX ?= /usr/local

# ============================================================================= #
# HELPERS
# ============================================================================= #

## help: Print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

# ============================================================================= #
# DEVELOPMENT
# ============================================================================= #

## run: Run the sesh application (development mode)
.PHONY: run
run:
	@echo "🚀 Running sesh in development mode (not installed to PATH)..."
	@echo "ℹ️  For system-wide use, run 'make install' first."
	@go run $(LDFLAGS) ./sesh/cmd/sesh/

## run/setup: Run the sesh setup wizard (development mode)
.PHONY: run/setup
run/setup:
	@echo "🚀 Running sesh setup wizard in development mode..."
	@echo "ℹ️  For system-wide use, run 'make install' first."
	@go run $(LDFLAGS) ./sesh/cmd/sesh/ --setup


# ============================================================================= #
# QUALITY CONTROL
# ============================================================================= #

## check-staticcheck: Check if staticcheck is installed
.PHONY: check-staticcheck
check-staticcheck:
	@if command -v staticcheck > /dev/null; then \
		echo "✅ staticcheck is installed"; \
	else \
		echo "⚠️ staticcheck not found, static analysis will be skipped"; \
		exit 1; \
	fi

## run-staticcheck: Run staticcheck if it exists
.PHONY: run-staticcheck
run-staticcheck: check-staticcheck
	@echo 'Running staticcheck...'
	@staticcheck ./... || echo "Note: staticcheck found issues (exit code: $$?)"

## check-golangci-lint: Check if golangci-lint is installed
.PHONY: check-golangci-lint
check-golangci-lint:
	@if command -v golangci-lint > /dev/null; then \
		echo "✅ golangci-lint is installed"; \
	else \
		echo "⚠️ golangci-lint not found, external linting will be skipped"; \
		exit 1; \
	fi

## run-golangci-lint: Run golangci-lint if it exists
.PHONY: run-golangci-lint
run-golangci-lint: check-golangci-lint
	@echo 'Running golangci-lint...'
	@golangci-lint run ./... || echo "Note: golangci-lint found issues (exit code: $$?)"

## audit: Tidy dependencies and format, vet and test all code
.PHONY: audit
audit:
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Formatting code...'
	go fmt ./...
	@echo 'Running lint...'
	@$(MAKE) lint
	@echo 'Running tests...'
	go test -race -vet=off ./...

## vendor: Tidy and vendor dependencies
.PHONY: vendor
vendor:
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Vendoring dependencies...'
	go mod vendor

## test: Run test suite
.PHONY: test
test:
	@echo 'Running tests...'
	@./scripts/test.sh

## test/short: Run only fast tests, skipping slow or external tests
.PHONY: test/short
test/short:
	@echo 'Running short tests only...'
	@go test -short ./...

## test/verbose: Run tests with verbose output
.PHONY: test/verbose
test/verbose:
	@echo 'Running tests with verbose output...'
	@go test -v ./...


## coverage: Run test suite with coverage
.PHONY: coverage
coverage:
	@echo 'Running tests with coverage...'
	@go test -coverprofile=coverage.txt ./... | grep -v "no test files" | grep -v "coverage: 0.0%" || true
	@echo 'Filtering out testutil, mock files, and interface-only files...'
	@grep -v "testutil\|mock\|provider/interfaces.go" coverage.txt > coverage.filtered.txt || true
	@go tool cover -html=coverage.filtered.txt -o coverage.html
	@echo "Coverage report generated at coverage.html"
	@rm -f coverage.filtered.txt

## coverage/func: Show function-level coverage statistics
.PHONY: coverage/func
coverage/func:
	@echo 'Generating function-level coverage report...'
	@go test -coverprofile=coverage.txt ./... 2>&1 | grep -v "no test files" | grep -v "coverage: 0.0%" || true
	@echo 'Filtering out testutil, mock files, and interface-only files...'
	@grep -v "testutil\|mock\|provider/interfaces.go" coverage.txt > coverage.filtered.txt || true
	@go tool cover -func=coverage.filtered.txt | grep -v "testutil\|mock\|provider/interfaces.go" || true
	@rm -f coverage.filtered.txt




## lint: Run linters
.PHONY: lint
lint:
	@echo 'Linting...'
	@echo 'Running go vet...'
	@go vet ./...
	@$(MAKE) run-golangci-lint || echo "Skipping external linting"
	@$(MAKE) run-staticcheck || echo "Skipping staticcheck"

# ============================================================================= #
# BUILD
# ============================================================================= #

## build: Build the sesh application
.PHONY: build
build:
	@echo "Building sesh..."
	@mkdir -p build
	@go build $(LDFLAGS) -o build/sesh ./sesh/cmd/sesh

## build/optimize: Build optimized binary (smaller size)
.PHONY: build/optimize
build/optimize:
	@echo "Building optimized binary..."
	@go build $(LDFLAGS) -ldflags="-s -w" -o build/sesh ./sesh/cmd/sesh

## build/all: Build for all supported platforms
.PHONY: build/all
build/all:
	@echo "Building for all platforms..."
	@mkdir -p bin/
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o build/bin/sesh-darwin-amd64 ./sesh/cmd/sesh
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o build/bin/sesh-darwin-arm64 ./sesh/cmd/sesh

## install: Install the application
.PHONY: install
install: clean build
	@echo "📦 Installing sesh..."
	@echo "Installing to ~/.local/bin (standard user location)"
	@mkdir -p $(HOME)/.local/bin
	@cp build/sesh $(HOME)/.local/bin/
	@chmod +x $(HOME)/.local/bin/sesh
	@echo "✅ Installation complete!"
	@if [[ ":$$PATH:" != *":$(HOME)/.local/bin:"* ]]; then \
		echo "⚠️  Please add ~/.local/bin to your PATH:"; \
		echo "   export PATH=\"$$HOME/.local/bin:\$$PATH\""; \
	fi
	
	@echo ""
	@echo "🚀 To get started:"
	@echo "   1. Run 'sesh --setup' to configure your MFA secret"
	@echo "   2. Then run 'sesh --service aws' to generate AWS temporary credentials"

# ============================================================================= #
# RELEASE
# ============================================================================= #

## release: Run GoReleaser in snapshot mode
.PHONY: release
release: confirm
	@echo "Running GoReleaser in snapshot mode..."
	@if command -v goreleaser > /dev/null; then \
		goreleaser release --snapshot --clean; \
	else \
		echo "goreleaser not found, skipping"; \
	fi

## release/homebrew: Prepare Homebrew formula
.PHONY: release/homebrew
release/homebrew:
	@echo "Preparing Homebrew formula..."
	@VERSION=$(VERSION) SHA256=$(shell shasum -a 256 bin/sesh-darwin-amd64 | cut -d ' ' -f 1) \
		envsubst < homebrew/sesh.rb.template > homebrew/sesh.rb
	@echo "Homebrew formula generated at homebrew/sesh.rb"

# ============================================================================= #
# VERSION INFO
# ============================================================================= #

## version: Print the current version
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"

# ============================================================================= #
# CLEAN
# ============================================================================= #

## clean: Remove build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -f coverage.out coverage.txt coverage.html
	@rm -rf bin/
	@rm -rf dist/
	@rm -rf build/