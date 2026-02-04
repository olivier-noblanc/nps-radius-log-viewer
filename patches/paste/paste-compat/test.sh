#!/bin/bash
# This script runs the compatibility tests for both the original paste and pastey.
# If any test fails, the script will exit with an error.

set -e  # Exit immediately if any command exits with a non-zero status

echo "========================================"
echo "Running tests with original paste crate (use_original feature)..."
echo "========================================"
cargo test --features use_original

echo "========================================"
echo "Running tests with pastey (default configuration)..."
echo "========================================"
cargo test

echo "========================================"
echo "All tests passed successfully!"
