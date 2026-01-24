# Makefile for dns - Zig DNS Library
#
# Usage:
#   make              - Build and run all tests
#   make test         - Run unit tests
#   make test-vectors - Run RFC test vectors
#   make clean        - Clean build artifacts
#   make help         - Show this help message

.PHONY: all build test test-unit test-vectors clean check fmt help

# Default target - build and run all tests
all: build test-unit test-vectors
	@echo ""
	@echo "All builds and tests completed successfully!"

# Build the library
build:
	@echo "Building dns library..."
	@zig build

# Run all standard tests (unit + vectors)
test: test-unit test-vectors
	@echo ""
	@echo "Standard tests completed"

# Run unit tests for all modules
test-unit:
	@echo "Running unit tests..."
	@zig build test --summary all

# Run RFC test vectors
test-vectors:
	@echo "Running RFC test vectors..."
	@zig build test-vectors --summary all

# Run RFC-specific test suites
test-rfc1035:
	@echo "Running RFC 1035 tests..."
	@zig build test-rfc1035 --summary all

test-rfc3596:
	@echo "Running RFC 3596 tests..."
	@zig build test-rfc3596 --summary all

test-rfc6891:
	@echo "Running RFC 6891 tests..."
	@zig build test-rfc6891 --summary all

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf zig-cache zig-out .zig-cache
	@echo "Clean complete"

# Check syntax without building
check:
	@echo "Checking syntax..."
	@find src -name "*.zig" -exec zig ast-check {} \;
	@echo "Syntax check complete"

# Format all Zig source files
fmt:
	@echo "Formatting source files..."
	@zig fmt src/ tests/ build.zig
	@echo "Format complete"

# Run tests with optimization levels
test-release-safe:
	@echo "Running tests with ReleaseSafe optimization..."
	@zig build test -Doptimize=ReleaseSafe --summary all

test-release-fast:
	@echo "Running tests with ReleaseFast optimization..."
	@zig build test -Doptimize=ReleaseFast --summary all

test-release-small:
	@echo "Running tests with ReleaseSmall optimization..."
	@zig build test -Doptimize=ReleaseSmall --summary all

# Run all optimization level tests
test-all-optimizations: test-unit test-release-safe test-release-fast test-release-small
	@echo "All optimization level tests completed"

# Continuous integration target
ci: clean build test
	@echo ""
	@echo "CI pipeline completed successfully!"

# Development workflow - quick iteration
dev: fmt check test-unit
	@echo "Development checks passed"

# Show help message
help:
	@echo "dns - Zig DNS Library Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Main Targets:"
	@echo "  all              - Build and run all tests (default)"
	@echo "  build            - Build the library"
	@echo "  test             - Run unit tests and RFC vectors"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-vectors     - Run RFC test vectors"
	@echo ""
	@echo "RFC-Specific Tests:"
	@echo "  test-rfc1035     - Run RFC 1035 (DNS) tests"
	@echo "  test-rfc3596     - Run RFC 3596 (AAAA) tests"
	@echo "  test-rfc6891     - Run RFC 6891 (EDNS0) tests"
	@echo ""
	@echo "Development Targets:"
	@echo "  clean            - Remove build artifacts"
	@echo "  check            - Check syntax without building"
	@echo "  fmt              - Format all Zig source files"
	@echo "  dev              - Quick development workflow (fmt + check + test-unit)"
	@echo ""
	@echo "Optimization Testing:"
	@echo "  test-release-safe  - Run tests with ReleaseSafe"
	@echo "  test-release-fast  - Run tests with ReleaseFast"
	@echo "  test-release-small - Run tests with ReleaseSmall"
	@echo "  test-all-optimizations - Run tests with all optimization levels"
	@echo ""
	@echo "CI/CD:"
	@echo "  ci               - Full CI pipeline (clean + build + all tests)"
	@echo ""
	@echo "Documentation:"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Run everything"
	@echo "  make test               # Quick test iteration"
	@echo "  make dev                # Development workflow"
	@echo "  make clean build test   # Clean rebuild and test"
	@echo ""
	@echo "Requirements:"
	@echo "  - Zig 0.15.1 or compatible"
