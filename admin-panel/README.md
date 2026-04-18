# eBPF Secure Port Knock - Admin Panel

A comprehensive web-based admin interface for managing the eBPF Secure Port Knock system. This admin panel provides real-time monitoring, configuration management, and diagnostic tools for your port knock security system.

## Features

### 🎯 Dashboard
- **Real-time System Status**: Monitor system health, XDP attachment, and overall status
- **Detailed Statistics**: View packet statistics, protection metrics, and authorization data
- **Performance Metrics**: Track success rates, pass rates, and replay attack blocks
- **Network Interfaces**: View available network interfaces for system configuration

### 🔐 Authorized IPs Management
- **View Active Authorizations**: List all currently authorized IPs with TTL information
- **Authorize New IPs**: Manually authorize specific IP addresses with configurable duration
- **Revoke Access**: Instantly revoke authorization for any IP
- **Bulk Operations**: Revoke all authorizations at once
- **Expired Entries**: Track and manage expired authorization entries

### ⚙️ Configuration Management
- **Knock Port Configuration**: Set the port where knock packets are received
- **Protected Ports**: Define which ports are protected by the system
- **Timeout Management**: Configure how long authorizations remain valid
- **HMAC Key Management**: Securely manage cryptographic keys (masked display for security)

### 🧪 Testing & Diagnostics
- **Knock Packet Test**: Send test knock packets to verify system functionality
- **Connectivity Test**: Test ping and port connectivity to verify network access
- **System Health Check**: Run comprehensive health diagnostics
- **Maps Integrity Check**: Verify BPF maps are accessible and functional

### 📊 Logs & Monitoring
- **Event Logging**: Track all system events with severity levels
- **Severity Filtering**: Filter events by severity (info, warning, error, critical)
- **System Logs**: View kernel and system logs related to the knock system
- **Log Export**: Export logs for analysis and troubleshooting

### 👤 Authentication
- **Secure Login**: JWT-based authentication for admin access
- **User Info Display**: Show current logged-in user and permissions
- **Session Management**: Secure logout and session handling

## Architecture

```
admin-panel/
├── backend/                    # Flask Python API server
│   ├── app/
│   │   ├── __init__.py        # Flask app factory
│   │   ├── bpf_accessor.py    # BPF map interaction module
│   │   └── routes/            # API endpoints
│   │       ├── auth.py        # Authentication endpoints
│   │       ├── dashboard.py   # Dashboard data endpoints
│   │       ├── config_routes.py # Configuration endpoints
│   │       ├── auth_ips.py    # IP authorization endpoints
│   │       ├── logs.py        # Event logging endpoints
│   │       └── test.py        # Testing/diagnostic endpoints
│   ├── config.py              # Configuration management
│   ├── requirements.txt       # Python dependencies
│   └── run.py                 # Backend entry point
│
└── frontend/                   # React TypeScript UI
    ├── src/
    │   ├── api/               # API client
    │   │   └── client.ts      # Axios API wrapper
    │   ├── contexts/          # React contexts
    │   │   └── AuthContext.tsx # Authentication state
    │   ├── pages/             # Page components
    │   │   ├── LoginPage.tsx
    │   │   ├── Dashboard.tsx
    │   │   ├── AuthorizedIPsPage.tsx
    │   │   ├── ConfigurationPage.tsx
    │   │   ├── TestingPage.tsx
    │   │   └── LogsPage.tsx
    │   ├── App.tsx            # Main app component
    │   ├── main.tsx           # React entry point
    │   └── index.css          # Tailwind CSS
    ├── vite.config.ts         # Vite configuration
    ├── tailwind.config.ts     # Tailwind CSS config
    └── package.json           # Node dependencies
```

## Installation & Setup

### Backend Setup

1. **Prerequisites**
   - Python 3.9+
   - pip package manager
   - Root access (for BPF map operations)

2. **Install Backend**
   ```bash
   cd admin-panel/backend
   cp .env.example .env
   # Edit .env to configure
   bash setup.sh
   ```

3. **Configure Environment**
   Edit `admin-panel/backend/.env`:
   ```
   FLASK_ENV=development
   SECRET_KEY=your-random-secret-key
   JWT_SECRET_KEY=your-jwt-secret-key
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your-password
   BPFFS_PATH=/sys/fs/bpf
   BPF_MAP_PATH=/sys/fs/bpf/knock
   API_PORT=5000
   ```

4. **Start Backend**
   ```bash
   cd admin-panel/backend
   python run.py
   ```

### Frontend Setup

1. **Prerequisites**
   - Node.js 18+
   - npm or yarn

2. **Install Frontend**
   ```bash
   cd admin-panel/frontend
   bash setup.sh
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   ```

4. **Build for Production**
   ```bash
   npm run build
   npm run preview
   ```

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `GET /api/auth/verify` - Verify JWT token
- `GET /api/auth/user-info` - Get current user info
- `POST /api/auth/logout` - User logout

### Dashboard
- `GET /api/dashboard/status` - System status overview
- `GET /api/dashboard/stats` - Detailed statistics
- `GET /api/dashboard/interfaces` - Network interfaces
- `GET /api/dashboard/logs` - System logs

### Configuration
- `GET /api/config/get` - Get current configuration
- `POST /api/config/update` - Update configuration
- `GET /api/config/keys/hmac` - Get HMAC key (masked)
- `POST /api/config/keys/hmac/update` - Update HMAC key
- `GET /api/config/timeout` - Get timeout setting
- `POST /api/config/timeout/update` - Update timeout

### Authorized IPs
- `GET /api/auth-ips/list` - List all authorized IPs
- `POST /api/auth-ips/authorize` - Authorize new IP
- `POST /api/auth-ips/revoke` - Revoke IP authorization
- `POST /api/auth-ips/revoke-all` - Revoke all IPs
- `GET /api/auth-ips/info/<ip>` - Get IP details
- `GET /api/auth-ips/stats` - Authorization statistics

### Logs
- `GET /api/logs/events` - Get event log
- `GET /api/logs/events/<id>` - Get specific event
- `GET /api/logs/system-logs` - Get system logs
- `POST /api/logs/clear` - Clear event log
- `GET /api/logs/stats` - Log statistics
- `GET /api/logs/export` - Export logs as JSON

### Testing
- `POST /api/test/knock-packet` - Send test knock packet
- `POST /api/test/connectivity` - Test connectivity
- `POST /api/test/config-reload` - Test config reload
- `GET /api/test/maps-integrity` - Check maps integrity
- `GET /api/test/system-health` - System health check

## Default Credentials

**Username:** `admin`  
**Password:** `changeme123`

⚠️ **IMPORTANT**: Change these credentials in production!

## Usage Guide

### Dashboard
1. Monitor real-time system status and statistics
2. View active authorizations and packet metrics
3. Check protection rates and success rates

### Managing Authorized IPs
1. Navigate to "Authorized IPs" page
2. Use the form to authorize new IPs
3. Set appropriate duration (5 seconds to 1 hour)
4. View active and expired entries

### Configuration
1. Navigate to "Configuration" page
2. Click "Edit" to modify settings
3. Update knock port, protected ports, timeout
4. Update HMAC key if needed (hex format)
5. Save changes

### Testing & Diagnostics
1. **Knock Packet Test**: Send a signed knock packet
   - Configure source IP, destination IP
   - Provide correct HMAC key
   - Verify success in results

2. **Connectivity Test**: Test network connectivity
   - Specify target IP and port
   - Tests both ping and port availability

3. **System Health Check**: Run comprehensive diagnostics
   - Verifies knockd running state
   - Checks XDP attachment
   - Validates map accessibility

4. **Maps Integrity Check**: Verify BPF maps
   - Tests all BPF maps are readable
   - Reports any access errors

### Monitoring Logs
1. Navigate to "Logs" page
2. Filter by severity (info, warning, error, critical)
3. View event descriptions and timestamps
4. Export logs for external analysis

## Database & Data Storage

### In-Memory Event Log
- Stores up to 1000 events in memory
- Lost on server restart (implement DB for persistence)
- Includes severity levels and timestamps

### BPF Map Access
- Reads from kernel BPF maps in `/sys/fs/bpf/knock/`
- No persistent database; data reflects current kernel state
- Maps include:
  - `config_map`: System configuration
  - `auth_map`: Authorized IP entries
  - `counters_map`: Debug counters

## Security Considerations

1. **Authentication**: JWT-based, change default credentials immediately
2. **HTTPS**: Use HTTPS in production, not HTTP
3. **Network**: Run on internal network only, not exposed to internet
4. **Root Access**: Backend needs sudo for certain operations
5. **HMAC Key**: Never expose full key; masked in UI
6. **API Token**: Keep JWT tokens secure, use secure cookie storage
7. **Logs**: Be careful with log export; may contain sensitive data

## Troubleshooting

### Backend won't start
```bash
# Check Python version
python --version

# Check dependencies installed
pip list | grep -i flask

# Verify port not in use
netstat -an | grep 5000
```

### Frontend won't build
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node version
node --version
```

### BPF maps not found
```bash
# Check if knockd is running
pgrep knockd

# Verify BPF filesystem mounted
mount | grep bpf

# Check map files exist
ls -la /sys/fs/bpf/knock/
```

### Permission denied errors
```bash
# Run backend with sudo
sudo python run.py

# Or configure sudoers for specific commands
```

## Performance Tips

1. **Refresh Intervals**
   - Dashboard: 5 seconds
   - Authorized IPs: 3 seconds
   - Adjust based on load

2. **Logging**
   - Reduce log retention in production
   - Implement database persistence
   - Use log rotation

3. **Scaling**
   - Use reverse proxy (nginx, Apache)
   - Run multiple backend instances
   - Implement proper database

## Development

### Adding New Features

1. **Backend**: Add routes in `app/routes/`
2. **Frontend**: Add pages in `src/pages/`
3. **API Client**: Update `src/api/client.ts`
4. **Context**: Update `src/contexts/` if needed

### Testing
- Backend tests in `backend/tests/`
- Frontend tests in `frontend/src/__tests__/`
- Integration tests use test endpoints

## Production Deployment

1. **Backend**
   - Use gunicorn: `gunicorn -w 4 -b 0.0.0.0:5000 app:app`
   - Use Nginx as reverse proxy
   - Enable SSL/TLS certificates

2. **Frontend**
   - Build: `npm run build`
   - Serve `dist/` folder via Nginx/Apache
   - Enable caching headers

3. **Environment**
   - Set `FLASK_ENV=production`
   - Use strong SECRET_KEY and JWT_SECRET_KEY
   - Enable CORS for specific domains only

## License

Same as parent eBPF Knock project

## Support

For issues or questions:
1. Check logs: `POST /api/test/system-health`
2. Review system diagnostics
3. Check backend/frontend console output
4. Review BPF kernel logs: `sudo dmesg`

