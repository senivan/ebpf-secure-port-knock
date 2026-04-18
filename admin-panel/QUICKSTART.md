# Quick Start Guide for Admin Panel

This guide will get you from zero to a fully functional admin panel in minutes.

## Option 1: Quick Setup (Recommended for Development)

### Step 1: Setup Backend

```bash
# Navigate to admin panel backend
cd admin-panel/backend

# Install dependencies (requires Python 3.9+)
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env if needed (default credentials work for testing)

# Start backend server
python run.py
```

Backend will be available at `http://localhost:5000`

### Step 2: Setup Frontend (New Terminal)

```bash
# Navigate to admin panel frontend
cd admin-panel/frontend

# Install dependencies (requires Node.js 18+)
npm install

# Start development server
npm run dev
```

Frontend will be available at `http://localhost:3000`

### Step 3: Login

1. Open browser to `http://localhost:3000`
2. Login with default credentials:
   - Username: `admin`
   - Password: `changeme123`
3. Start managing your port knock system!

## Option 2: Docker Setup (Production-Ready)

### Prerequisites
- Docker and Docker Compose installed
- BPF maps mounted from host

### Quick Start

```bash
# Build and start both services
docker-compose up --build

# Services will be available at:
# Backend: http://localhost:5000
# Frontend: http://localhost:3000
```

See `docker-compose.yml` for detailed configuration.

## Option 3: Standalone Deployment

### Backend Only
```bash
# For headless server deployment
cd admin-panel/backend

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
export FLASK_ENV=production
export ADMIN_PASSWORD=your-secure-password
export ADMIN_USERNAME=your-username

# Run with production server
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()
```

### Frontend Only
```bash
# Build frontend static files
cd admin-panel/frontend
npm run build

# Serve with nginx/apache (see nginx.conf example)
# Or use any static file server
```

## Testing

### Run Full Test Suite
```bash
chmod +x admin-panel/tests.sh
bash admin-panel/tests.sh
```

### Sample Test Output
```
════════════════════════════════════════════════════════════
  COMPREHENSIVE ADMIN PANEL TESTS
════════════════════════════════════════════════════════════

1. HEALTH CHECKS
✓ PASS: Backend health check

2. AUTHENTICATION TESTS
✓ PASS: Login successful, got token
✓ PASS: Token verification successful
✓ PASS: Invalid credentials correctly rejected

... (more tests)

TEST SUMMARY
Total Tests:  33
Passed:       33
Failed:       0
Pass Rate:    100%

✓ ALL TESTS PASSED
```

## Common Tasks

### Change Admin Password
Edit `admin-panel/backend/.env`:
```
ADMIN_PASSWORD=your-new-password
```

Then restart backend.

### View Real-time Logs
Terminal 1 (Backend):
```bash
tail -f backend.log
```

Terminal 2 (Frontend):
```bash
npm run dev  # Shows build and client logs
```

### Test Knock Packet
1. Go to Testing → Knock Packet Tab
2. Enter source/destination IPs
3. Enter correct HMAC key
4. Click "Send Knock Packet"
5. Results shown immediately

### Authorize an IP
1. Go to Authorized IPs Page
2. Enter IP address
3. Select duration
4. Click "Authorize"
5. IP appears in active list with TTL countdown

### Monitor System Health
1. Go to Testing → System Health
2. Click "Run System Health Check"
3. Review health score and individual checks

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│     React Frontend (Port 3000)              │
│  - Dashboard                                 │
│  - IP Management                             │
│  - Configuration                             │
│  - Testing & Diagnostics                     │
│  - Logs                                      │
└────────────┬────────────────────────────────┘
             │ HTTPS / CORS
             ▼
┌─────────────────────────────────────────────┐
│     Flask Backend (Port 5000)               │
│  - JWT Authentication                        │
│  - RESTful API Endpoints                     │
│  - BPF Map Access Layer                      │
│  - System Integration                        │
└────────────┬────────────────────────────────┘
             │ /sys/fs/bpf
             ▼
┌─────────────────────────────────────────────┐
│     eBPF Kernel Programs                    │
│  - XDP Program (knock_kern.bpf)             │
│  - BPF Maps (config, auth, counters)        │
└─────────────────────────────────────────────┘
```

## File Structure

```
admin-panel/
├── backend/
│   ├── app/
│   │   ├── routes/          # API endpoints
│   │   ├── bpf_accessor.py  # BPF interaction
│   │   └── __init__.py      # App factory
│   ├── config.py            # Configuration
│   ├── run.py               # Entry point
│   ├── requirements.txt     # Dependencies
│   └── .env.example         # Config template
│
├── frontend/
│   ├── src/
│   │   ├── pages/           # Page components
│   │   ├── contexts/        # State management
│   │   ├── api/             # API client
│   │   ├── App.tsx          # Main component
│   │   └── index.css        # Styles
│   ├── package.json         # Dependencies
│   └── vite.config.ts       # Build config
│
├── README.md                # Main documentation
├── TESTING.md               # Testing guide
└── QUICKSTART.md            # This file
```

## Troubleshooting

### "Cannot connect to backend"
- Check backend is running: `ps aux | grep python`
- Check port 5000 is listening: `netstat -an | grep 5000`
- Check firewall doesn't block: `sudo ufw allow 5000`

### "BPF maps not found"
- Verify knockd is running: `pgrep knockd`
- Check BPF FS mounted: `mount | grep bpf`  
- Verify maps exist: `ls -la /sys/fs/bpf/knock/`

### "Authentication failed"
- Verify credentials in .env
- Check backend logs for errors
- Try restarting backend

### "Frontend won't connect to backend"
- Check CORS is enabled in Flask
- Verify backend URL in vite.config.ts
- Check browser console for actual error

### "Port already in use"
- Backend port 5000: `sudo kill -9 $(lsof -t -i :5000)`
- Frontend port 3000: `sudo kill -9 $(lsof -t -i :3000)`

## Next Steps

1. **Production Deployment**
   - Use gunicorn for backend
   - Use nginx for frontend
   - Enable SSL/TLS
   - Set strong credentials

2. **Scaling**
   - Add load balancer
   - Multiple backend instances
   - Database for persistence

3. **Monitoring**
   - Export logs to centralized logging
   - Set up alerting
   - Monitor performance metrics

4. **Security Hardening**
   - Implement rate limiting
   - Add IP whitelisting
   - Enable audit logging
   - Use secrets management

## Performance Tips

- Dashboard refresh: 5 seconds (adjustable)
- IP list refresh: 3 seconds (adjustable)
- Log limit: 100 events (configurable)
- Database: Consider for large deployments

## Getting Help

1. Check TESTING.md for detailed test information
2. Review logs: `docker logs container-id`
3. Check system health: `/api/test/system-health`
4. Verify BPF maps: `/api/test/maps-integrity`

## Development Mode

```bash
# Terminal 1: Start backend with debug logging
export FLASK_DEBUG=1
python admin-panel/backend/run.py

# Terminal 2: Start frontend with HMR
cd admin-panel/frontend
npm run dev

# Terminal 3: Monitor tests
watch -n 2 'bash admin-panel/tests.sh'
```

## Security Reminders

⚠️ **Before going to production:**
1. Change admin password in .env
2. Generate new SECRET_KEY and JWT_SECRET_KEY
3. Enable HTTPS with valid certificates
4. Restrict network access
5. Run backend with appropriate user permissions
6. Implement rate limiting
7. Set up access logs and monitoring

Enjoy your admin panel! 🚀
