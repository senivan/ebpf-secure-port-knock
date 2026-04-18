#!/bin/bash

# Backend setup script
set -e

echo "Setting up admin panel backend..."

# Copy environment file if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example - please configure it"
fi

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Generate flask secret key
if ! grep -q "SECRET_KEY=your-secret" .env; then
    echo ".env already configured"
else
    echo "Note: Please configure .env file before running the server"
fi

echo "Backend setup complete!"
echo ""
echo "To run the server:"
echo "  python run.py"
echo ""
echo "Common environment variables:"
echo "  FLASK_ENV=development|production"
echo "  API_PORT=5000"
echo "  ADMIN_USERNAME=admin"
echo "  ADMIN_PASSWORD=changeme123"
