# Installation

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux kernel ≥ 5.7 | XDP native/generic mode; BTF required at `/sys/kernel/btf/vmlinux` |
| `clang` with BPF target | Ubuntu: `apt install clang llvm` |
| `bpftool` | Ubuntu: `apt install linux-tools-$(uname -r)` |
| `libbpf` + dev headers | Ubuntu: `apt install libbpf-dev` |
| `pkg-config` | Ubuntu: `apt install pkg-config` |
| `make`, `cc` | Standard build tools |
| Root / `CAP_NET_ADMIN` | Required to attach XDP programs and manage pinned maps |

For the **admin panel** only:

| Requirement | Notes |
|---|---|
| Python 3.9+ | Backend (Flask) |
| Node.js 18+ | Frontend (React + Vite) |
| `npm` | Front-end package manager |

## Verify BTF is available

```bash
ls -lh /sys/kernel/btf/vmlinux
```

If the file is missing, upgrade to a BTF-enabled kernel or rebuild with `CONFIG_DEBUG_INFO_BTF=y`.

## Clone and build

```bash
git clone https://github.com/senivan/ebpf-secure-port-knock.git
cd ebpf-secure-port-knock
make all
```

`make all` performs three steps in order:

1. **`include/vmlinux.h`** — generated via `scripts/gen_vmlinux_h.sh`, which runs `bpftool btf dump file /sys/kernel/btf/vmlinux format c`.
2. **`build/knock_kern.bpf.o`** — compiled with `clang -target bpf`.
3. **`build/knockd`** and **`build/knock-client`** — compiled with the host `cc` + libbpf.

### Build outputs

| Binary | Description |
|--------|-------------|
| `build/knock_kern.bpf.o` | eBPF object loaded into the kernel |
| `build/knockd` | Daemon + admin CLI |
| `build/knock-client` | Raw-packet knock sender |

### Compiler overrides

```bash
make all BPF_CLANG=clang-16 USER_CC=gcc
```

| Variable | Default | Description |
|---|---|---|
| `BPF_CLANG` | `clang` | Compiler for the eBPF object |
| `USER_CC` | `cc` | Compiler for user-space binaries |
| `PKG_CONFIG` | `pkg-config` | pkg-config binary |
| `BPF_CFLAGS` | `-g -O2 -target bpf ...` | Extra BPF compile flags |
| `USER_CFLAGS` | `-g -O2 -Wall -Wextra` | Extra user-space compile flags |

### Clean build artifacts

```bash
make clean
```

Removes the entire `build/` directory. The generated `include/vmlinux.h` is kept.

## Installing the admin panel

### Backend

```bash
cd admin-panel/backend
cp .env.example .env
# edit .env — set ADMIN_USERNAME, ADMIN_PASSWORD, SECRET_KEY, JWT_SECRET_KEY
bash setup.sh
python run.py
```

### Frontend

```bash
cd admin-panel/frontend
bash setup.sh
npm run dev        # development server on :3000
```

Production build:

```bash
npm run build
npm run preview
```

### Docker (optional)

```bash
cd admin-panel
docker compose up --build
```

Default ports: backend `5000`, frontend `3000`.

## Verifying the installation

No-root smoke test (CLI validation only):

```bash
make test-config
```

Full integration smoke test (root required):

```bash
make test
```

See [[Testing]] for all available test targets.
