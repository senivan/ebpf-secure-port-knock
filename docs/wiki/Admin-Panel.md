# Admin Panel

The admin panel is a separate service that provides a browser-based UI and a REST API for operating the knock gate without using the CLI.

## Architecture

```
Browser
  └─▶ React/Vite UI (port 3000)
        └─▶ Flask REST API (port 5000)
              └─▶ BPF maps at /sys/fs/bpf/knock_gate/
```

The backend reads pinned BPF maps via `bpftool` calls (or a direct reader) and exposes a JSON API secured with JWT tokens.

## Setup

### Backend

```bash
cd admin-panel/backend
cp .env.example .env
bash setup.sh
python run.py
```

### Frontend

```bash
cd admin-panel/frontend
bash setup.sh
npm run dev          # dev server on :3000
```

### Docker

```bash
cd admin-panel
docker compose up --build
```

## Environment variables (`.env`)

| Variable | Default | Description |
|---|---|---|
| `API_PORT` | `5000` | Port the Flask server listens on |
| `ADMIN_USERNAME` | — | Login username |
| `ADMIN_PASSWORD` | — | Login password |
| `SECRET_KEY` | — | Flask session secret (set a strong random value) |
| `JWT_SECRET_KEY` | — | JWT signing secret (set a strong random value) |
| `BPFFS_PATH` | `/sys/fs/bpf` | Root of the BPF filesystem |
| `BPF_MAP_PATH` | `/sys/fs/bpf/knock` | Path to pinned knock maps |

> **Security:** Change default credentials and set strong random secrets before exposing the panel on any network. Keep the panel on trusted networks only.

## REST API

All endpoints (except `/api/auth/login`) require a JWT bearer token:

```
Authorization: Bearer <token>
```

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Obtain a JWT token. Body: `{"username": "…", "password": "…"}` |
| `POST` | `/api/auth/logout` | Invalidate the current token |
| `GET` | `/api/auth/me` | Return info about the currently authenticated user |

### Dashboard

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/dashboard/status` | System status: config, counters, active IP count, last knock snapshot |
| `GET` | `/api/dashboard/stats` | Detailed knock and protection statistics |
| `GET` | `/api/dashboard/interfaces` | List network interfaces |
| `GET` | `/api/dashboard/logs` | Recent system log lines (`?lines=N`, default 100) |

### Authorized IPs

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/auth-ips/list` | List all entries in the active session map with TTL info |
| `POST` | `/api/auth-ips/authorize` | Manually authorize an IP. Body: `{"ip": "1.2.3.4", "duration_ms": 5000}` |
| `POST` | `/api/auth-ips/revoke` | Revoke authorization. Body: `{"ip": "1.2.3.4"}` |
| `POST` | `/api/auth-ips/revoke-all` | Revoke all currently authorized IPs |
| `GET` | `/api/auth-ips/info/<ip>` | Get authorization info for a specific IP |
| `GET` | `/api/auth-ips/stats` | Authorization map statistics (active, expired, avg TTL) |

### Configuration

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config/get` | Read current configuration from BPF map |
| `POST` | `/api/config/update` | Update configuration. Body: `{knock_port, protected_ports, timeout_ms, hmac_key}` |
| `GET` | `/api/config/ports/protected` | Get list of protected ports |
| `GET` | `/api/config/ports/knock` | Get knock port and timeout |
| `GET` | `/api/config/keys/hmac` | Get HMAC key (masked, last 4 chars visible) |
| `POST` | `/api/config/keys/hmac/update` | Update HMAC key. Body: `{"hmac_key": "<64 hex>"}` |
| `GET` | `/api/config/timeout` | Get current `timeout_ms` |
| `POST` | `/api/config/timeout/update` | Update timeout. Body: `{"timeout_ms": 10000}` |

### Logs

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/logs` | Retrieve recent log lines |

### Testing / diagnostics

| Method | Path | Description |
|---|---|---|
| Various | `/api/test/…` | Diagnostic endpoints used by the test runner |

## Frontend pages

| Page | Route | Description |
|---|---|---|
| Login | `/login` | Credential form, obtains JWT |
| Dashboard | `/` | Live system status, counters, last knock |
| Authorized IPs | `/auth-ips` | View, add, and revoke authorized IPs |
| Configuration | `/config` | View and update gate configuration |
| Logs | `/logs` | Tail recent system logs |
| Testing | `/testing` | In-browser diagnostics panel |

## Running tests

```bash
cd admin-panel
bash run-tests.sh
```

Or individually:

```bash
# backend
cd admin-panel/backend
python3 -m pytest tests/ -v

# frontend
cd admin-panel/frontend
npm run test
```
