# User Management

Each user is identified by a numeric `user_id` (0–1023) and a 32-byte HMAC key. The user ID is encoded in the upper 16 bits of `session_id_hi` in every knock packet, allowing the XDP program to select the correct key from `user_key_map` without requiring a user-database lookup.

## Users file

The recommended way to load users at daemon startup is a CSV file:

```
# user_id,hmac_key_hex
100,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
101,aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
```

- Lines starting with `#` are comments.
- `hmac_key_hex` must be exactly 64 hex characters (32 bytes).
- Up to `KNOCK_MAX_USERS` (1024) users are supported.

Pass the file at daemon startup:

```bash
sudo ./build/knockd daemon --ifname eth0 --users-file /etc/knock/users.csv --protect 22
```

---

## Runtime admin commands

All admin commands operate on pinned maps at `/sys/fs/bpf/knock_gate/` and **do not require a daemon restart**. Root is required.

### Register a new user

```bash
sudo ./build/knockd register-user \
  --user-id 102 \
  --hmac-key 0011223344556677889900aabbccddeeff00112233445566778899aabbccddeef
```

Inserts a new entry into `user_key_map`. Fails if the user ID is already registered.

### Rotate a user's key

```bash
sudo ./build/knockd rotate-user-key \
  --user-id 102 \
  --hmac-key <new-64-hex> \
  --grace-ms 5000
```

Sets the new key as `active_key` and moves the old key to `previous_key` with a grace window of `--grace-ms` milliseconds. During the grace window the XDP program accepts knocks signed with **either** the active or the previous key, enabling zero-downtime key rotation.

`--grace-ms` is optional; it defaults to `0` (no grace window).

### Revoke a user

```bash
sudo ./build/knockd revoke-user --user-id 102
```

Removes the user's entry from `user_key_map`. Any subsequent knock from this user will increment `unknown_user` and be dropped.

### List registered users

```bash
sudo ./build/knockd list-users
```

Prints all user IDs currently registered in `user_key_map` along with key version numbers.

---

## Session ID encoding

The 64-bit session ID is split into two 32-bit fields in the knock packet:

```
session_id_hi [31:16]  =  user_id   (16 bits, max 65535)
session_id_hi [15: 0]  =  random    (16 bits)
session_id_lo [31: 0]  =  random    (32 bits)
```

Relevant constants in `include/shared.h`:

```c
#define KNOCK_USER_ID_SHIFT  16U
#define KNOCK_USER_ID_MASK   0xffff0000U
```

The knock client automatically encodes `--user-id` into `session_id_hi` when generating an AUTH packet. When using `--session-id` directly (e.g. for BIND/DEAUTH), the caller is responsible for ensuring the correct user_id is present in bits 31-16.

---

## Key rotation grace window

When `rotate-user-key` is called the kernel's `user_key_state` struct stores:

| Field | Description |
|---|---|
| `active_key[32]` | The new key — validated first |
| `previous_key[32]` | The old key — validated only if `active_key` fails and the grace window has not expired |
| `key_version` | Monotonically increasing counter |
| `grace_until_ns` | Monotonic timestamp after which `previous_key` is no longer tried |

The `grace_key_used` stat counter increments each time a knock is authenticated via the grace (previous) key.
