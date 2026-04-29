.PHONY: build run dev check test clean setup

# Build in release mode
build:
	cargo build --release

# Run in release mode
run: build
	cargo run --release

# Run in debug mode with verbose logging
dev:
	RUST_LOG=debug cargo run

# Type-check without building
check:
	cargo check

# Run all tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Clean build artifacts
clean:
	cargo clean

# Initial setup: copy example config and build
setup:
	@test -f config.toml || cp config.example.toml config.toml
	cargo build --release
	@echo "Done. Edit config.toml if needed, then run: make run"

# Format code
fmt:
	cargo fmt

# Lint with clippy
lint:
	cargo clippy -- -D warnings
