#!/bin/bash

# Development setup script for ldap-auth-rs

set -e

echo "🚀 Setting up LDAP Auth RS development environment..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed. Please install from https://rustup.rs/"
    exit 1
fi

echo "✅ Rust is installed"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker is not installed. You'll need it to run Redis."
    echo "   Install from https://docs.docker.com/get-docker/"
else
    echo "✅ Docker is installed"
fi

# Copy environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created. Please update it with your configuration."
fi

# Start Redis with Docker (if available)
if command -v docker &> /dev/null; then
    echo "🐳 Starting Redis container..."
    docker run -d \
        --name ldap-auth-redis \
        -p 6379:6379 \
        redis:7-alpine || echo "⚠️  Redis container already exists or failed to start"
    echo "✅ Redis is running on localhost:6379"
fi

# Install git hooks
echo "🪝 Installing git hooks..."
if [ -d .git ]; then
    git config core.hooksPath .githooks
    echo "✅ Git hooks installed (pre-commit will run cargo fmt)"
else
    echo "⚠️  Not a git repository, skipping hooks installation"
fi

# Build the project
echo "🔨 Building the project..."
cargo build

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Update .env with your configuration"
echo "  2. Run 'cargo test' to run tests"
echo "  3. Run 'cargo run' to start the application"
echo "  4. API will be available at http://localhost:8080"
echo "  5. LDAP will be available at ldap://localhost:3389"
echo ""
