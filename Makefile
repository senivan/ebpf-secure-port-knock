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

.PHONY: all clean run test help

all: $(BPF_OBJ) $(USER_BIN) $(KNOCK_CLIENT_BIN)

help:
	@echo "Targets:"
	@echo "  make all          Build eBPF object + user-space binaries"
	@echo "  make run IFACE= HMAC_KEY= PROTECT=   Attach XDP gate with signed knock config"
	@echo "  make test         Run integration smoke test (requires root)"
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
	@if [ -z "$(IFACE)" ] || [ -z "$(HMAC_KEY)" ] || [ -z "$(PROTECT)" ]; then \
		echo "error: set IFACE, HMAC_KEY and PROTECT"; \
		echo "example: make run IFACE=eth0 HMAC_KEY=<64hex> PROTECT=22,443 KNOCK_PORT=40000 TIMEOUT_MS=5000"; \
		exit 1; \
	fi
	sudo ./$(USER_BIN) --ifname $(IFACE) --hmac-key $(HMAC_KEY) --protect $(PROTECT) \
		$(if $(KNOCK_PORT),--knock-port $(KNOCK_PORT),) \
		$(if $(TIMEOUT_MS),--timeout-ms $(TIMEOUT_MS),) \
		$(if $(DURATION_SEC),--duration-sec $(DURATION_SEC),)

test: all
	sudo ./scripts/test_e2e.sh

clean:
	rm -rf $(BUILD_DIR)
