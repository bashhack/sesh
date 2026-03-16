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

# Package list excluding scripts/ (standalone utilities, not part of the module)
PACKAGES = $(shell go list ./... | grep -v /scripts)

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

## pre-commit: Run pre-commit checks on all files
.PHONY: pre-commit
pre-commit: format/check
	@echo 'Checking compilation...'
	@go build $(PACKAGES)
	@echo 'Running go vet...'
	@go vet $(PACKAGES)
	@$(MAKE) lint/golangci
	@echo '✅ All pre-commit checks passed!'

## dev/setup/hooks: Install git hooks for pre-commit checks
.PHONY: dev/setup/hooks
dev/setup/hooks:
	@echo 'Installing git hooks...'
	@if [ ! -f .githooks/pre-commit ]; then \
		echo '❌ Error: .githooks/pre-commit not found'; \
		exit 1; \
	fi
	@mkdir -p .git/hooks
	@cp .githooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo '✅ Git hooks installed'
	@echo 'Pre-commit hook will now check formatting and run go vet before each commit'

## format: Format all Go code with goimports
.PHONY: format
format:
	@echo 'Formatting Go code...'
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@goimports -w -local github.com/bashhack/sesh $$(find . -name '*.go' -not -path "./vendor/*")
	@echo '✅ Code formatted'

## format/check: Check if code is properly formatted (non-destructive)
.PHONY: format/check
format/check:
	@echo 'Checking Go code formatting...'
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@if [ -n "$$(goimports -l -local github.com/bashhack/sesh $$(find . -name '*.go' -not -path './vendor/*'))" ]; then \
		echo "❌ The following files need formatting:"; \
		goimports -l -local github.com/bashhack/sesh $$(find . -name '*.go' -not -path './vendor/*'); \
		echo "Run 'make format' to fix"; \
		exit 1; \
	fi
	@echo '✅ All files properly formatted'

## lint: Run linters
.PHONY: lint
lint:
	@echo 'Formatting code...'
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@goimports -w -local github.com/bashhack/sesh $$(find . -name '*.go' -not -path "./vendor/*")
	@echo 'Vetting code...'
	go vet $(PACKAGES)
	$(MAKE) check-staticcheck
	staticcheck $(PACKAGES)
	@echo '✅ Linting complete'

## lint/golangci: Run golangci-lint (comprehensive linting tool)
.PHONY: lint/golangci
lint/golangci:
	@echo 'Running golangci-lint...'
	@REQUIRED_VERSION="2.6.2"; \
	INSTALL_NEEDED=false; \
	if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not found"; \
		INSTALL_NEEDED=true; \
	else \
		CURRENT_VERSION=$$(golangci-lint --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
		if [ "$$CURRENT_VERSION" != "$$REQUIRED_VERSION" ]; then \
			echo "golangci-lint version $$CURRENT_VERSION found, but v$$REQUIRED_VERSION required"; \
			INSTALL_NEEDED=true; \
		fi; \
	fi; \
	if [ "$$INSTALL_NEEDED" = "true" ]; then \
		echo "Installing golangci-lint v$$REQUIRED_VERSION..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$(go env GOPATH)/bin v$$REQUIRED_VERSION; \
	fi
	@golangci-lint run ./...
	@echo '✅ golangci-lint complete'

## lint/fieldalignment: Show fieldalignment suggestions safely (runs in /tmp, non-destructive)
.PHONY: lint/fieldalignment
lint/fieldalignment:
	@echo 'Checking fieldalignment (safe mode - no files modified)...'
	@if ! command -v fieldalignment >/dev/null 2>&1; then \
		echo "Installing fieldalignment..."; \
		go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest; \
	fi
	@./scripts/fieldalignment_check.sh

## check-staticcheck: Check if staticcheck is installed
.PHONY: check-staticcheck
check-staticcheck:
	@if ! command -v staticcheck >/dev/null 2>&1; then \
		echo "Error: 'staticcheck' is not installed. Installing..."; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi

## security-scan: Run security vulnerability scanner
.PHONY: security-scan
security-scan:
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Error: 'gosec' is not installed. Installing..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	gosec ./...

## audit: Tidy dependencies and format, vet and test all code
.PHONY: audit
audit:
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Formatting code...'
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@goimports -w -local github.com/bashhack/sesh $$(find . -name '*.go' -not -path "./vendor/*")
	@echo 'Vetting code...'
	go vet $(PACKAGES)
	$(MAKE) check-staticcheck
	staticcheck $(PACKAGES)
	$(MAKE) lint/golangci
	@echo 'Running tests...'
	go test -race -vet=off $(PACKAGES)
	@echo '✅ Audit complete'

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
	@go test -v $(PACKAGES)

## test/short: Run only fast tests, skipping slow or external tests
.PHONY: test/short
test/short:
	@echo 'Running short tests only...'
	@go test -short $(PACKAGES)

## test/verbose: Run tests with verbose output
.PHONY: test/verbose
test/verbose:
	@echo 'Running tests with verbose output...'
	@go test -v $(PACKAGES)

## coverage: Run test suite with coverage
.PHONY: coverage
coverage:
	@echo 'Running tests with coverage...'
	@go test -coverprofile=coverage.txt $(PACKAGES) | grep -v "no test files" | grep -v "coverage: 0.0%" || true
	@echo 'Filtering out testutil, mock files, scripts, interface-only files, and main.go...'
	@grep -v "testutil\|mock\|provider/interfaces.go\|scripts/\|cmd/sesh/main.go" coverage.txt > coverage.filtered.txt || true
	@go tool cover -html=coverage.filtered.txt -o coverage.html
	@echo "Coverage report generated at coverage.html"
	@rm -f coverage.filtered.txt

## coverage/func: Show function-level coverage statistics
.PHONY: coverage/func
coverage/func:
	@echo 'Generating function-level coverage report...'
	@go test -coverprofile=coverage.txt $(PACKAGES) 2>&1 | grep -v "no test files" | grep -v "coverage: 0.0%" || true
	@grep -v "testutil\|mock\|provider/interfaces.go\|scripts/\|cmd/sesh/main.go" coverage.txt > coverage.filtered.txt || true
	@go tool cover -func=coverage.filtered.txt | grep -v "testutil\|mock\|provider/interfaces.go\|scripts/\|cmd/sesh/main.go" || true
	@rm -f coverage.filtered.txt

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
