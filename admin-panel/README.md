# Admin Panel

Admin UI and API for operating the eBPF knock system from this repository.

## Scope

- Backend API for status, config, auth IP management, logs, and diagnostics
- Frontend web UI for operators
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
- Access to bpffs and knock maps when running against a live system

## Backend setup

```bash
cd admin-panel/backend
cp .env.example .env
bash setup.sh
python run.py
```

Important environment variables in `.env`:

- `API_PORT` (default `5000`)
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `BPFFS_PATH` (default `/sys/fs/bpf`)
- `BPF_MAP_PATH` (default `/sys/fs/bpf/knock`)
- `SECRET_KEY`
- `JWT_SECRET_KEY`

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

## Tests

Run both backend and frontend checks:

```bash
cd admin-panel
bash run-tests.sh
```

Manual commands:

```bash
cd admin-panel/backend
python3 -m pytest tests/ -v

cd admin-panel/frontend
npm run test
```

## Docker (optional)

```bash
cd admin-panel
docker compose up --build
```

Default container ports:

- Backend: `5000`
- Frontend: `3000`

## Security notes

- Change default admin credentials before exposing the service
- Set strong `SECRET_KEY` and `JWT_SECRET_KEY`
- Keep the panel on trusted networks only
- Prefer HTTPS and proper reverse-proxy hardening in production
