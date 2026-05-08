# Admin Panel

Admin UI and API for operating the eBPF knock system from this repository.

## Scope

- Backend API for status, config, daemon control, auth IP management, logs, and diagnostics
- Frontend web UI for operators
- Mock/demo mode when live pinned maps are not available
- Optional Docker compose setup for local bring-up

## Layout

- `admin-panel/backend`: Flask API
- `admin-panel/frontend`: React + Vite UI
- `admin-panel/docker-compose.yml`: local multi-service compose file
- `admin-panel/run-tests.sh`: backend/frontend test runner

## Prerequisites

- Python 3.9+
- Node.js 18+
- `npm`
- Access to bpffs and pinned knock maps when running against a live system
- `sudo` access if you want the backend to manage the real `knockd` process

## Backend setup

```bash
cd admin-panel/backend
cp .env.example .env
bash setup.sh
python run.py
```

The backend supports live and mock accessors:

- `USE_MOCK_BPF=auto`: use mock mode only in tests
- `USE_MOCK_BPF=true`: force mock/demo mode
- `USE_MOCK_BPF=false`: require the live accessor

Important environment variables:

- `API_PORT` (default `5000`)
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`
- `BPFFS_PATH` (default `/sys/fs/bpf`)
- `BPF_MAP_PATH` (default `/sys/fs/bpf/knock_gate`)
- `KNOCKD_BIN` (default `/home/user/ebpf-secure-port-knock/build/knockd`)
- `KNOCKD_CONFIG_PATH` (default `/tmp/knock_admin_config.json`)
- `KNOCKD_LOG_PATH` (default `/tmp/knockd-admin.log`)
- `KNOCKD_DEFAULT_IFACE` (default `eth0`)
- `KNOCKD_USERS_FILE` (default empty)
- `KNOCKD_PIN_DIR` (default `/sys/fs/bpf/knock_gate`)
- `KNOCKD_USE_SUDO` (default `true`)
- `KNOCKD_SABBATH_MODE` (default `false`): refuse to start `knockd` on local Saturdays and pass `--sabbath-mode`
- `USE_MOCK_BPF` (default `auto`)
- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `CORS_ORIGINS` comma-separated trusted frontend origins, for example `https://admin.example.com`
- `SECURITY_HSTS_ENABLED` (default `true` in production, `false` otherwise)

Live daemon management works by launching the repo's `build/knockd daemon` command with the configured interface, users file or HMAC key, protected ports, and pin directory.

## Frontend setup

```bash
cd admin-panel/frontend
bash setup.sh
npm run dev
```

Build production assets:

```bash
npm run build
npm run preview
```

## Current capabilities

- Dashboard status and summary stats
- Daemon status plus start, stop, and restart controls
- Configuration editing with optional restart-after-save behavior
- Auth IP inspection and revoke flows
- Log and diagnostics views
- Mock mode for local UI/API development without a live XDP attachment

## Tests

Run the bundled admin-panel checks:

```bash
cd admin-panel
bash run-tests.sh
```

Manual commands:

```bash
cd admin-panel/backend
python3 -m pytest tests/ -v

cd admin-panel/frontend
npm run build
```

Notes:

- The frontend currently has a production build command but no `npm run test` script.
- `run-tests.sh` attempts backend pytest execution and frontend dependency setup for you.

## Docker (optional)

```bash
cd admin-panel
mkdir -p certs
# Place a valid TLS certificate and key at:
#   certs/admin-panel.crt
#   certs/admin-panel.key
docker compose up --build
```

Default container ports:

- Reverse proxy: `80` redirects to `443`
- HTTPS admin panel: `443`
- Backend and frontend remain on the internal compose network

Required compose environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`

## Security notes

- Change default admin credentials before exposing the service
- Set strong `SECRET_KEY` and `JWT_SECRET_KEY`
- Set `CORS_ORIGINS` to the exact HTTPS origin(s) that should access the API
- Terminate TLS at nginx with valid certificates; HTTP is redirected to HTTPS
- Keep the panel on trusted networks only
- Treat the daemon-control endpoints as privileged operations
- Keep the reverse-proxy security headers enabled in production
