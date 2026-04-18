BPF_CLANG ?= clang
USER_CC ?= cc
PKG_CONFIG ?= pkg-config

BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86 -D__BPF__ -Wall -Wextra
USER_CFLAGS ?= -g -O2 -Wall -Wextra
USER_LDLIBS ?= $(shell $(PKG_CONFIG) --libs libbpf)
USER_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf)

BUILD_DIR := build
BPF_OBJ := $(BUILD_DIR)/knock_kern.bpf.o
USER_BIN := $(BUILD_DIR)/knockd
KNOCK_CLIENT_BIN := $(BUILD_DIR)/knock-client
USER_COMMON_SRCS := src/user/cli_common.c
KNOCKD_SRCS := src/user/knock_user.c src/user/xdp_loader.c $(USER_COMMON_SRCS)
KNOCK_CLIENT_SRCS := src/user/knock_client.c src/user/net_checksum.c $(USER_COMMON_SRCS)

.PHONY: all clean run test test-netns test-ssh test-user-auth test-user-rotation test-user-admin test-user-all test-user-pressure test-config all-test help

all: $(BPF_OBJ) $(USER_BIN) $(KNOCK_CLIENT_BIN)

help:
	@echo "Targets:"
	@echo "  make all          Build eBPF object + user-space binaries"
	@echo "  make run IFACE= USERS_FILE= PROTECT= Attach XDP gate with per-user signed knock config"
	@echo "  make test         Run integration smoke test (requires root)"
	@echo "  make test-netns   Run network-namespace integration scenario (requires root)"
	@echo "  make test-ssh     Run SSH functional netns scenario (requires root + sshd)"
	@echo "  make test-user-auth      Run per-user registration/isolation tests (requires root)"
	@echo "  make test-user-rotation  Run per-user key rotation tests (requires root)"
	@echo "  make test-user-admin     Run per-user admin live-update tests (requires root)"
	@echo "  make test-user-pressure  Run per-user pressure tests (requires root)"
	@echo "  make test-config         Run CLI config validation test"
	@echo "  make test-user-all       Run all per-user feature tests"
	@echo "  make all-test            Run all test suites"
	@echo "  make clean        Remove build artifacts"

include/vmlinux.h:
	./scripts/gen_vmlinux_h.sh include/vmlinux.h

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BPF_OBJ): src/bpf/knock_kern.bpf.c include/shared.h include/vmlinux.h | $(BUILD_DIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -Iinclude -c src/bpf/knock_kern.bpf.c -o $(BPF_OBJ)

$(USER_BIN): $(KNOCKD_SRCS) include/shared.h include/knock_crypto.h | $(BUILD_DIR)
	$(USER_CC) $(USER_CFLAGS) $(USER_CPPFLAGS) -Iinclude $(KNOCKD_SRCS) -o $(USER_BIN) $(USER_LDLIBS)

$(KNOCK_CLIENT_BIN): $(KNOCK_CLIENT_SRCS) include/shared.h include/knock_crypto.h | $(BUILD_DIR)
	$(USER_CC) $(USER_CFLAGS) -Iinclude $(KNOCK_CLIENT_SRCS) -o $(KNOCK_CLIENT_BIN)

run: all
	@if [ -z "$(IFACE)" ] || [ -z "$(USERS_FILE)" ] || [ -z "$(PROTECT)" ]; then \
		echo "error: set IFACE, USERS_FILE and PROTECT"; \
		echo "example: make run IFACE=eth0 USERS_FILE=/etc/knock/users.csv PROTECT=22,443 KNOCK_PORT=40000 TIMEOUT_MS=5000"; \
		exit 1; \
	fi
	sudo ./$(USER_BIN) daemon --ifname $(IFACE) --users-file $(USERS_FILE) --protect $(PROTECT) \
		$(if $(HMAC_KEY),--hmac-key $(HMAC_KEY),) \
		$(if $(KNOCK_PORT),--knock-port $(KNOCK_PORT),) \
		$(if $(TIMEOUT_MS),--timeout-ms $(TIMEOUT_MS),) \
		$(if $(REPLAY_WINDOW_MS),--replay-window-ms $(REPLAY_WINDOW_MS),) \
		$(if $(DURATION_SEC),--duration-sec $(DURATION_SEC),)

test: all
	sudo ./scripts/test_e2e.sh

test-netns: all
	sudo ./scripts/test_e2e_netns.sh

test-ssh: all
	sudo ./scripts/test_e2e_netns_ssh.sh

test-user-auth: all
	sudo ./scripts/test_e2e_user_auth.sh

test-user-rotation: all
	sudo ./scripts/test_e2e_user_rotation.sh

test-user-admin: all
	sudo ./scripts/test_e2e_user_admin.sh

test-config: all
	bash ./scripts/test_cli_replay_window_validation.sh

test-user-pressure: all
	sudo bash ./scripts/test_e2e_user_pressure.sh

test-user-all: test-user-auth test-user-rotation test-user-admin

all-test: test test-netns test-ssh test-config test-user-pressure test-user-all

clean:
	rm -rf $(BUILD_DIR)
