#!/bin/bash

# Comprehensive setup script for admin panel
# Installs and configures both backend and frontend

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/backend"
FRONTEND_DIR="${SCRIPT_DIR}/frontend"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}\n"
}

print_info() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Step 1: System Requirements
print_header "Checking System Requirements"

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    print_info "Python 3 found: $PYTHON_VERSION"
else
    print_error "Python 3 not found. Please install Python 3.9+"
    exit 1
fi

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    print_info "Node.js found: $NODE_VERSION"
else
    print_warn "Node.js not found. Frontend setup will be skipped."
fi

# Check npm
if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    print_info "npm found: $NPM_VERSION"
fi

# Check git
if command -v git &> /dev/null; then
    print_info "Git found"
else
    print_warn "Git not found"
fi

# Step 2: Backend Setup
print_header "Setting Up Backend"

cd "${BACKEND_DIR}"

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
else
    print_info "Virtual environment already exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate || . venv/Scripts/activate

# Install dependencies
print_info "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env if not exists
if [ ! -f ".env" ]; then
    print_info "Creating .env file from template..."
    cp .env.example .env
    print_warn "Please edit .env file to configure backend settings"
else
    print_info ".env file already exists"
fi

# Step 3: Frontend Setup
print_header "Setting Up Frontend"

if command -v npm &> /dev/null; then
    cd "${FRONTEND_DIR}"
    
    # Check if node_modules exists
    if [ ! -d "node_modules" ]; then
        print_info "Installing Node.js dependencies..."
        npm install
    else
        print_info "Node.js dependencies already installed"
    fi
    
    # Build check
    print_info "Verifying build configuration..."
    npm run build 2>&1 | head -5 || true
    
else
    print_warn "Skipping frontend setup (Node.js not installed)"
fi

# Step 4: Project Structure Verification
print_header "Verifying Project Structure"

# Check key files
FILES_TO_CHECK=(
    "backend/app/__init__.py"
    "backend/app/bpf_accessor.py"
    "backend/app/routes/auth.py"
    "backend/app/routes/dashboard.py"
    "backend/config.py"
    "backend/run.py"
    "frontend/src/App.tsx"
    "frontend/src/main.tsx"
    "frontend/package.json"
    "README.md"
    "TESTING.md"
    "QUICKSTART.md"
)

MISSING_FILES=0
for file in "${FILES_TO_CHECK[@]}"; do
    if [ -f "${SCRIPT_DIR}/${file}" ]; then
        print_info "Found: ${file}"
    else
        print_warn "Missing: ${file}"
        ((MISSING_FILES++))
    fi
done

if [ $MISSING_FILES -eq 0 ]; then
    print_info "All required files present"
fi

# Step 5: Summary and Next Steps
print_header "Setup Complete!"

cat << EOF
${GREEN}✓ Admin Panel installation complete!${NC}

${BLUE}Next Steps:${NC}

1. ${YELLOW}Configure Backend${NC}
   Edit ${BACKEND_DIR}/.env with your settings:
   - ADMIN_PASSWORD (change from default)
   - HMAC_KEY (if needed)
   - Other configuration options

2. ${YELLOW}Start Backend${NC}
   cd ${BACKEND_DIR}
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   python run.py
   Backend will be available at http://localhost:5000

3. ${YELLOW}Start Frontend${NC} (new terminal)
   cd ${FRONTEND_DIR}
   npm run dev
   Frontend will be available at http://localhost:3000

4. ${YELLOW}Login${NC}
   Default credentials:
   Username: admin
   Password: changeme123

5. ${YELLOW}Run Tests${NC}
   After starting backend, run:
   bash ${SCRIPT_DIR}/tests.sh

${BLUE}Documentation:${NC}
- README.md - Full feature documentation
- QUICKSTART.md - Quick start guide  
- TESTING.md - Testing and diagnostics

${BLUE}Production Deployment:${NC}
- Use Docker: docker-compose up
- Review nginx.conf for reverse proxy setup
- Generate new SECRET_KEY and JWT_SECRET_KEY
- Enable HTTPS with valid certificates

${YELLOW}Important Security Reminders:${NC}
⚠️  Change admin password before production use
⚠️  Use HTTPS in production
⚠️  Restrict network access
⚠️  Keep backend and frontend on same network

Happy administrating! 🚀

EOF

# Optional: Try to start services if requested
if [ "$1" = "--start" ]; then
    print_header "Starting Services"
    
    print_info "Starting backend..."
    cd "${BACKEND_DIR}"
    source venv/bin/activate && python run.py &
    BACKEND_PID=$!
    
    print_info "Backend started (PID: $BACKEND_PID)"
    print_warn "To start frontend in another terminal:"
    echo "  cd ${FRONTEND_DIR} && npm run dev"
    
    print_warn "Press Ctrl+C to stop backend"
    wait $BACKEND_PID
fi

exit 0
