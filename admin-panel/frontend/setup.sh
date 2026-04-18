#!/bin/bash

# Frontend setup script
set -e

echo "Setting up admin panel frontend..."

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

echo "Frontend setup complete!"
echo ""
echo "To start development server:"
echo "  npm run dev"
echo ""
echo "To build for production:"
echo "  npm run build"
