# Credential Encryption at Rest

Sieve's whole value proposition is that it holds your real credentials so your AI agents never have to. That only works if an attacker with access to the database file — through backup leak, disk snapshot, accidental sync to the wrong place, or SQLi read — doesn't walk away with every credential you've ever stored.

This page documents how credential encryption works, what it defends against, what it does not, and how to deploy it.

## What gets encrypted

The sensitive field on every connection: `connections.config`. That's the JSON blob that holds:

- OAuth refresh tokens and access tokens (Gmail, Drive, Calendar, Contacts, Sheets, Docs)
- Google OAuth `client_secret`
- LLM API keys (Anthropic, OpenAI, Gemini, Bedrock)
- HTTP proxy auth headers and API keys
- AWS access keys

Everything else stays as-is: policy configs, roles, bearer-token hashes (which are already SHA-256 hashes, not plaintext), audit log rows. Bearer tokens have 256 bits of entropy and are hashed-only on disk, so there's nothing to recover there even with full DB access.

## Threat coverage

| Attack | Before | After |
|---|---|---|
| Stolen DB file / backup / snapshot (Sieve stopped) | total credential compromise | ciphertext only |
| Stolen DB while Sieve is running | total compromise | DB alone useless; KEK lives only in the running process |
| SQLi read / read-only DB access from a buggy endpoint | total compromise | ciphertext only |
| Live root on the running host | total compromise | **still total compromise** (out of scope — attacker can `ptrace` or read `/proc/<pid>/mem`) |
| Host reboot / crash / OOM | transparent | **human must re-enter the passphrase** (intentional cost) |

The trade-off is explicit: by keeping the key **off the machine at rest** we get strong protection against every cold-disk attack, at the cost of requiring a human (or a supervisor-managed secret) to unlock Sieve after every restart.

## Design

Standard envelope encryption — no novel crypto, all primitives from the Go standard library plus `golang.org/x/crypto/argon2`.

### Keys

- **Passphrase** → you type it at startup. Never stored on disk.
- **KEK** (Key Encryption Key) — 32 bytes, derived from the passphrase via `argon2id(passphrase, salt, t=3, m=256 MiB, p=4, keyLen=32)`. Held only in process memory.
- **DEK** (Data Encryption Key) — 32 bytes, fresh random per `connections` row. The DEK encrypts the JSON config under AES-256-GCM. The DEK itself is AES-256-GCM-wrapped under the KEK and stored alongside the ciphertext.

Per-record DEKs mean future key rotation is cheap: re-wrap the tiny DEK blobs, don't touch the larger ciphertext payloads.

### Startup flow

```
  passphrase ─► argon2id(salt, params) ─► KEK
                                           │
                                           ▼
                             decrypt crypto_meta.kek_check
                                           │
                          ┌────────────────┴────────────────┐
                          ▼                                 ▼
                     sentinel matches                   mismatch
                          │                                 │
                          ▼                                 ▼
                     service starts                  exit non-zero
                                                   (wrong passphrase)
```

The `kek_check` verifier is decrypted **before** any write happens — that catches a typo before it silently corrupts new records. The sentinel plaintext is a fixed 16-byte string; only the round-trip-decrypts-cleanly property matters.

### Schema (connections table)

| Column | Type | Meaning |
|---|---|---|
| `id` | TEXT PK | Connection ID |
| `connector_type` | TEXT | `google`, `http_proxy`, `mcp_proxy`, etc. |
| `display_name` | TEXT | Human label |
| `config_ciphertext` | BLOB | AES-256-GCM(DEK, config_json) |
| `config_nonce` | BLOB | 12-byte GCM nonce for the payload |
| `dek_wrapped` | BLOB | AES-256-GCM(KEK, DEK) |
| `dek_nonce` | BLOB | 12-byte GCM nonce for the wrapped DEK |
| `enc_version` | INTEGER | Algorithm tag; currently `1` |
| `created_at` | DATETIME | |

Plus a singleton `crypto_meta` row: `argon2_salt`, `argon2_params` (JSON, so params can be retuned later), `kek_check` (verifier).

### Write path (`Add`, `UpdateConfig`)

1. Marshal config to JSON.
2. Generate a fresh 32-byte DEK.
3. `config_ciphertext, config_nonce = AES-GCM-seal(DEK, json)`.
4. `dek_wrapped, dek_nonce = AES-GCM-seal(KEK, DEK)`.
5. Insert/update the row with all five blobs plus `enc_version = 1`.

`UpdateConfig` rotates the DEK on every write — cheaper than checking whether the existing DEK can be reused, and keeps each ciphertext blob independent.

### Read path (`GetWithConfig`, `InitAll`)

1. Select the five blobs.
2. `DEK = AES-GCM-open(KEK, dek_wrapped, dek_nonce)` — fails closed if tampered.
3. `json = AES-GCM-open(DEK, config_ciphertext, config_nonce)` — fails closed if tampered.
4. Unmarshal JSON → config map.

Tampering with either blob flips the GCM auth tag and the call errors out. No partial or silent-success path exists.

## Passphrase intake

When Sieve starts, it looks for the passphrase in this order:

1. **TTY** — if stdin is an interactive terminal, prompt with echo off. First-run setup prompts twice and verifies the entries match.
2. **`SIEVE_PASSPHRASE_FILE`** env var → read the file at that path. The env var holds a *path*, not the passphrase itself. Good for Docker secrets, systemd `LoadCredential=`, Kubernetes mounted secrets.
3. **FD 3** — file descriptor 3, if open. This is the convention systemd's `LoadCredential=` uses when it hands a secret to the unit without touching the filesystem.
4. **No source** → startup fails with a clear error. Sieve refuses to run without a key.

**Never an env var holding the passphrase itself.** Env variables leak through:
- `/proc/<pid>/environ` (any process with the same UID can read them)
- `ps auxe`
- crash dumps
- child processes that inherit the environment

A file holds the secret in one place you control the permissions on; the env var tells Sieve where to find it. This is the same split systemd, Docker, and Kubernetes use for their own secret-handling.

## First-run setup

The first time Sieve starts against a fresh database, there is no `crypto_meta` row. Sieve:

1. Prompts for a passphrase twice (to catch typos).
2. Generates a random 16-byte salt.
3. Derives the KEK.
4. Encrypts the verifier sentinel.
5. Writes the `crypto_meta` row.

From then on, startup uses the `Load` path — derive KEK from the entered passphrase, verify it against the sentinel, arm the keyring.

## Locked state

If Sieve is started without a passphrase source (or you explicitly lock the keyring), every endpoint that needs to read or write credentials returns:

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{"error": "service locked: passphrase required"}
```

This covers all credential-touching routes: `/api/v1/connections/*/ops/*`, `/proxy/*`, `/gmail/v1/*`, the LLM-models probe in the web UI. Non-credential admin pages (audit log, token list, policy editor) continue to work so you can diagnose.

## Passphrase rotation

`sieve passphrase change` (provided by the `cmd/sieve` entrypoint):

1. Prompts for the current passphrase, derives the old KEK, verifies the sentinel.
2. Prompts twice for the new passphrase, derives a new KEK with a fresh salt.
3. Opens a transaction.
4. For every `connections` row: unwrap the DEK with the old KEK, re-wrap it with the new KEK, update `dek_wrapped` + `dek_nonce` in place.
5. Update `crypto_meta` with the new salt, params, and verifier.
6. Commit.

The actual ciphertext (`config_ciphertext`) is **never touched** — only the tiny wrapped-DEK blobs are rewritten. Rotation is O(connections), not O(credential bytes).

If any step fails the transaction rolls back and the old passphrase is still valid. The in-memory KEK is only swapped after a successful commit.

## Deployment recipes

### Interactive (dev machine)

Just run `./sieve serve`. Type the passphrase when prompted.

### Docker Compose with a mounted secret

```yaml
# docker-compose.yml
services:
  sieve:
    image: sieve:latest
    environment:
      SIEVE_PASSPHRASE_FILE: /run/secrets/sieve-passphrase
    secrets:
      - sieve-passphrase
    ports: [ "19816:19816", "19817:19817" ]

secrets:
  sieve-passphrase:
    file: ./sieve-passphrase.txt  # 0600 on host; contains the passphrase only
```

### systemd

```ini
# /etc/systemd/system/sieve.service
[Service]
ExecStart=/usr/local/bin/sieve serve
LoadCredential=sieve-passphrase:/etc/sieve/passphrase
Environment=SIEVE_PASSPHRASE_FILE=%d/sieve-passphrase
```

`LoadCredential=` reads the file as root, drops a copy at `$CREDENTIALS_DIRECTORY/sieve-passphrase` (mode 0400, owned by the service user), and Sieve picks it up via `SIEVE_PASSPHRASE_FILE`. The original file on disk can stay restricted to root.

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata: { name: sieve-passphrase }
stringData:
  passphrase: "correct-horse-battery-staple"
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: sieve
          image: sieve:latest
          env:
            - name: SIEVE_PASSPHRASE_FILE
              value: /etc/sieve/passphrase/passphrase
          volumeMounts:
            - { name: pp, mountPath: /etc/sieve/passphrase, readOnly: true }
      volumes:
        - name: pp
          secret: { secretName: sieve-passphrase }
```

## Out of scope (explicit)

- **KMS / Vault / OS keyring providers.** Current design keeps the trust model simple (one passphrase, one admin). A KMS provider would offload key custody to AWS/GCP — useful for some deployments, but a different project from the passphrase-at-startup model shipped here.
- **Memory hardening** (mlock, zero-on-free beyond KEK lifecycle events). An attacker with root on the running host can read the KEK from `/proc/<pid>/mem` or attach `gdb`/`ptrace`; mlock only marginally raises that bar while adding operational complexity. If you have a cold-boot threat model, air-gap the host.
- **SQLCipher / whole-DB encryption.** Coarser than field-level (loses per-record DEKs), and SQLCipher's rotation story is more invasive than re-wrapping a handful of DEKs.
- **Encryption of `audit_log.params`.** Audit rows contain the request payload, which can be sensitive (email bodies, API request bodies). They are in scope for a follow-up but kept out of this change because operators typically view them in the UI, and adding decryption there has knock-on UX costs. Filter audit retention instead for now (`audit.retention_days` in `sieve.yaml`).

## Verification

The shipped test suite enforces the invariants:

```bash
# Unit tests: primitives, keyring lifecycle, rotation
go test ./internal/secrets/...

# Encrypted round-trip, tampered-ciphertext fails closed,
# locked-state error surfaces, and an explicit on-disk plaintext check
# that scans the SQLite file for credential markers.
go test ./internal/connections/...

# Full suite with race detector
go test -race ./...
```

The on-disk check (`TestNoPlaintextOnDisk` in `internal/connections/encrypted_test.go`) is the one operators usually want to see: it writes a config with distinctive marker strings, checkpoints WAL, reads the raw SQLite file, and grep's for the markers. If any marker appears in the file, the test fails — encryption is broken.

To do the same check by hand on a real install:

```bash
# After saving some connections:
sqlite3 ./data/sieve.db 'SELECT hex(config_ciphertext) FROM connections;' \
  | xxd -r -p \
  | strings  # should produce nothing recognizable
```

You should see no refresh-token prefixes (`1//…`), no Google `client_secret` values, and no literal provider API keys.
