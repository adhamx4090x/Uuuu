# CXA Makefile
# Build automation for the CXA Cryptographic System

.PHONY: all build build-rust build-go build-python build-all clean test test-rust test-go test-python test-integration lint lint-rust lint-go lint-python docs deploy help

# Default target
all: build

# Build targets
build: build-rust build-go build-python

build-rust:
	@echo "Building Rust core modules..."
	cd rust-core && cargo build --release

build-go:
	@echo "Building Go services..."
	cd go-services && go build -o bin/ ./...

build-python:
	@echo "Building Python package..."
	cd python-core && poetry build

build-all: build-rust build-go build-python
	@echo "Build complete. Artifacts in:"
	@echo "  - rust-core/target/release/"
	@echo "  - go-services/bin/"
	@echo "  - python-core/dist/"

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	cd rust-core && cargo clean
	rm -rf go-services/bin/*
	rm -rf python-core/dist/*
	rm -rf dist/*
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete."

# Test targets
test: test-rust test-go test-python

test-rust:
	@echo "Running Rust tests..."
	cd rust-core && cargo test --all

test-go:
	@echo "Running Go tests..."
	cd go-services && go test ./...

test-python:
	@echo "Running Python tests..."
	cd python-core && poetry run pytest

test-integration:
	@echo "Running integration tests..."
	cd tests/integration && poetry run pytest

test-all: test-rust test-go test-python test-integration
	@echo "All tests complete."

# Lint targets
lint: lint-rust lint-go lint-python

lint-rust:
	@echo "Running Rust linters..."
	cd rust-core && cargo fmt --check
	cd rust-core && cargo clippy -- -D warnings

lint-go:
	@echo "Running Go linters..."
	cd go-services && go fmt ./...
	cd go-services && go vet ./...

lint-python:
	@echo "Running Python linters..."
	cd python-core && poetry run flake8 cxa/
	cd python-core && poetry run black --check cxa/

# Documentation targets
docs:
	@echo "Generating documentation..."
	@echo "See docs/ directory for available documentation."

# Deployment targets
deploy: build-all
	@echo "Preparing deployment package..."
	@bash build_linux.sh dist

# Docker targets
docker-build:
	@echo "Building Docker images..."
	docker build -f Dockerfile.api -t cxa/api:latest .
	docker build -f Dockerfile.python -t cxa/python:latest .

docker-run:
	@echo "Starting Docker services..."
	docker-compose up -d

docker-stop:
	@echo "Stopping Docker services..."
	docker-compose down

# Installation targets
install: build-all
	@echo "Installing CXA..."
	@echo "See docs/deployment.md for installation instructions."

# Help target
help:
	@echo "CXA Cryptographic System - Build Automation"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  all              Build all components (default)"
	@echo "  build            Build all components"
	@echo "  build-rust       Build Rust core modules"
	@echo "  build-go         Build Go services"
	@echo "  build-python     Build Python package"
	@echo "  build-all        Build all and show artifact locations"
	@echo ""
	@echo "Test targets:"
	@echo "  test             Run all tests"
	@echo "  test-rust        Run Rust tests"
	@echo "  test-go          Run Go tests"
	@echo "  test-python      Run Python tests"
	@echo "  test-integration Run integration tests"
	@echo ""
	@echo "Lint targets:"
	@echo "  lint             Run all linters"
	@echo "  lint-rust        Run Rust linters"
	@echo "  lint-go          Run Go linters"
	@echo "  lint-python      Run Python linters"
	@echo ""
	@echo "Clean targets:"
	@echo "  clean            Remove all build artifacts"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build     Build Docker images"
	@echo "  docker-run       Start Docker services"
	@echo "  docker-stop      Stop Docker services"
	@echo ""
	@echo "Other targets:"
	@echo "  docs             Generate documentation"
	@echo "  deploy           Build and prepare deployment"
	@echo "  install          Install CXA"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build all"
	@echo "  make test         # Run all tests"
	@echo "  make clean        # Clean artifacts"
	@echo "  make deploy       # Build deployment package"
