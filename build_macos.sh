#!/bin/bash
set -e

# CXA Build Script for macOS
# This script builds all CXA components for macOS distribution

echo "=========================================="
echo "CXA Cryptographic System - macOS Build"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Rust
    if ! command -v rustc &> /dev/null; then
        print_error "Rust not found. Please install Rust 1.70 or later."
        print_status "Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        exit 1
    fi
    
    # Check Go
    if ! command -v go &> /dev/null; then
        print_warning "Go not found. Skipping Go service build."
        BUILD_GO=false
    else
        BUILD_GO=true
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found. Please install Python 3.10 or later."
        print_status "Install from: https://www.python.org/downloads/mac-osx/"
        exit 1
    fi
    
    # Check Poetry
    if ! command -v poetry &> /dev/null; then
        print_warning "Poetry not found. Will use pip instead."
        USE_POETRY=false
    else
        USE_POETRY=true
    fi
    
    # Check Xcode command line tools
    if ! command -v xcode-select &> /dev/null; then
        print_error "Xcode command line tools not found."
        print_status "Install with: xcode-select --install"
        exit 1
    fi
    
    print_status "Prerequisites check complete."
}

# Build Rust core modules
build_rust_core() {
    print_status "Building Rust core modules..."
    
    cd rust-core
    
    # Clean previous builds
    cargo clean
    
    # Build release
    cargo build --release
    
    # Verify build artifacts
    if [ -d "target/release" ]; then
        print_status "Rust build complete. Artifacts in target/release/"
    else
        print_error "Rust build failed."
        exit 1
    fi
    
    cd ..
}

# Build Go services
build_go_services() {
    if [ "$BUILD_GO" = false ]; then
        print_warning "Skipping Go services build (Go not found)."
        return
    fi
    
    print_status "Building Go services..."
    
    cd go-services
    
    # Build API server
    print_status "Building API server..."
    CGO_ENABLED=0 GOOS=darwin go build -o bin/api-server ./api-server
    
    # Build event monitor
    print_status "Building event monitor..."
    CGO_ENABLED=0 GOOS=darwin go build -o bin/event-monitor ./event-monitor
    
    # Build event processor
    print_status "Building event processor..."
    CGO_ENABLED=0 GOOS=darwin go build -o bin/event-processor ./event-processor
    
    # Build monitor
    print_status "Building monitor..."
    CGO_ENABLED=0 GOOS=darwin go build -o bin/monitor ./monitor
    
    # Verify artifacts
    if [ -d "bin" ]; then
        print_status "Go build complete. Artifacts in go-services/bin/"
    else
        print_error "Go build failed."
        exit 1
    fi
    
    cd ..
}

# Build Python package
build_python_package() {
    print_status "Building Python package..."
    
    cd python-core
    
    if [ "$USE_POETRY" = true ]; then
        poetry build
    else
        pip install setuptools wheel
        python setup.py sdist bdist_wheel
    fi
    
    cd ..
}

# Create distribution package
create_distribution() {
    print_status "Creating distribution package..."
    
    DIST_DIR="dist"
    mkdir -p "$DIST_DIR"
    
    # Create package name with timestamp
    PACKAGE_NAME="cxa-macos-arm64-$(date +%Y%m%d-%H%M%S)"
    PKG_DIR="$DIST_DIR/$PACKAGE_NAME"
    mkdir -p "$PKG_DIR"
    
    # Copy binaries
    if [ -d "rust-core/target/release" ]; then
        cp -r rust-core/target/release/*.dylib "$PKG_DIR/" 2>/dev/null || true
        cp -r rust-core/target/release/cxa-* "$PKG_DIR/" 2>/dev/null || true
    fi
    
    if [ -d "go-services/bin" ]; then
        mkdir -p "$PKG_DIR/bin"
        cp go-services/bin/* "$PKG_DIR/bin/"
    fi
    
    # Copy Python package
    mkdir -p "$PKG_DIR/python"
    if [ -d "python-core/dist" ]; then
        cp python-core/dist/* "$PKG_DIR/python/"
    fi
    
    # Copy configuration
    cp config/default.yml "$PKG_DIR/"
    
    # Copy documentation
    mkdir -p "$PKG_DIR/docs"
    cp README.md "$PKG_DIR/"
    cp -r docs/* "$PKG_DIR/docs/"
    
    # Copy scripts
    mkdir -p "$PKG_DIR/scripts"
    cp scripts/*.sh "$PKG_DIR/scripts/"
    chmod +x "$PKG_DIR/scripts"/*.sh
    
    # Create tarball
    cd "$DIST_DIR"
    tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
    rm -rf "$PACKAGE_NAME"
    
    cd ..
    
    print_status "Distribution created: $DIST_DIR/${PACKAGE_NAME}.tar.gz"
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    # Rust tests
    cd rust-core
    cargo test --all
    cd ..
    
    # Python tests
    if [ "$USE_POETRY" = true ]; then
        cd python-core
        poetry run pytest
        cd ..
    else
        pip install pytest
        pytest python-core/
    fi
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all       Build all components (default)"
    echo "  rust      Build only Rust core modules"
    echo "  go        Build only Go services"
    echo "  python    Build only Python package"
    echo "  dist      Create distribution package"
    echo "  test      Run all tests"
    echo "  clean     Clean build artifacts"
    echo "  help      Show this help message"
}

# Main entry point
main() {
    case "${1:-all}" in
        all)
            check_prerequisites
            build_rust_core
            build_go_services
            build_python_package
            create_distribution
            ;;
        rust)
            check_prerequisites
            build_rust_core
            ;;
        go)
            check_prerequisites
            build_go_services
            ;;
        python)
            check_prerequisites
            build_python_package
            ;;
        dist)
            check_prerequisites
            build_rust_core
            build_go_services
            build_python_package
            create_distribution
            ;;
        test)
            run_tests
            ;;
        clean)
            print_status "Cleaning build artifacts..."
            cd rust-core && cargo clean && cd ..
            rm -rf go-services/bin/*
            rm -rf python-core/dist/*
            rm -rf dist/*
            print_status "Clean complete."
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            print_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
