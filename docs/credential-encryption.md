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

1. **`SIEVE_PASSPHRASE_FILE`** env var → read the file at that path. The env var holds a *path*, not the passphrase itself. Good for Docker secrets, systemd `LoadCredential=`, Kubernetes mounted secrets. Takes precedence over the TTY prompt so that operators with wired-up credential plumbing aren't re-prompted on every start.
2. **FD 3** — file descriptor 3, if open. This is the convention systemd's `LoadCredential=` uses when it hands a secret to the unit without touching the filesystem.
3. **TTY** — if stdin is an interactive terminal, prompt with echo off. First-run setup prompts twice and verifies the entries match. (Only consulted if neither of the above is configured.)
4. **No source** → startup fails with a clear error. Sieve refuses to run without a key.

When the passphrase comes from a file or FD 3, the "confirm" step that the TTY uses during first-run setup is skipped — there's nothing to confirm against a static source.

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

You can change Sieve's passphrase at any time, and every connection you've already added keeps working under the new value. Sieve gives you two ways to do it:

- **From the admin UI** — for routine rotations on a running Sieve. Recommended.
- **From the command line** — for when Sieve is stopped, or for recovery situations.

Both paths produce the same end state and the same audit-log entry, so it doesn't matter which one you pick — choose whichever fits the moment.

### When to rotate

Rotate the passphrase whenever it's been seen by someone who shouldn't keep access:

- A teammate who knew the passphrase has left.
- The passphrase was typed into a chat, ticket, or screen-share and you'd like a clean cutover.
- You're following a scheduled rotation policy.
- You've recovered from a suspected compromise and want a fresh key.

Rotation is cheap regardless of how many connections you have — it's not "re-encrypt every credential", it's "swap the small key that *unlocks* the credentials". Even with hundreds of connections it completes in a few seconds. (See [Why rotation is fast](#why-rotation-is-fast) below.)

### From the admin UI (recommended)

1. Open the admin UI at `http://127.0.0.1:19816/settings`.
2. Scroll to the **Security** card.
3. Fill in your current passphrase, then your new passphrase twice (the second time confirms there was no typo).
4. Click **Rotate passphrase**.

The button enters a busy state for one to three seconds while Sieve derives the new key, and then the page reloads with a green confirmation showing how many credentials were re-keyed. **Sieve does not need to be restarted** — it picks up the new passphrase immediately, and you can keep working in the same admin session.

If the rotation fails (wrong current passphrase, mismatched confirmation, etc.) the page redraws with a clear error and **none of the typed values are echoed back** — you re-type from scratch. Nothing is changed on disk until everything has succeeded.

### From the command line

Use this when Sieve is stopped, or in recovery situations where the admin UI isn't available. **Stop the running Sieve process first** — if you don't, the rotation will be blocked by the database lock and exit with code `6`.

```
$ sieve --rotate-passphrase
Current passphrase: ********
New passphrase: ********
Confirm passphrase: ********
sieve: passphrase rotated. 7 credential records re-wrapped.
$ echo $?
0
```

The command does not start any network listeners — it runs the rotation and exits. Start Sieve again the normal way with the new passphrase when you're done.

**Exit codes** (so scripts can branch on specific failures):

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic / unexpected failure |
| 2 | Wrong current passphrase |
| 3 | New-passphrase confirmation mismatch |
| 4 | New passphrase identical to current |
| 5 | Keyring not initialized — run `--setup` once first |
| 6 | Database is locked — another Sieve process is holding it, or another rotation is already in progress |

The CLI surface currently expects a real terminal for the prompts. If you need scripted rotation, drive the admin-UI form from a headless browser, or wrap the CLI in an `expect`-style script.

### What agents experience while rotation is happening

Rotation takes one to three seconds, and during that window any agent that hits Sieve to use a credential gets a *temporary* error back:

```
HTTP/1.1 503 Service Unavailable
Retry-After: 5
Content-Type: text/plain

rotation in progress, retry shortly
```

Anthropic's agent SDKs, the MCP host, and any client that already retries on `503` will retry automatically and continue working — your agents don't need to be reconfigured or restarted. Agents will **never** see a partially-rotated state where some credentials work and others don't; rotation is all-or-nothing from the outside.

### How the UI form is hardened

The rotation form is the most sensitive form Sieve has — anyone who can submit it can change your passphrase. It carries protections that the other admin forms don't need:

- **Agents can't reach it.** The form lives on the admin-only port (19816) and explicitly rejects any request carrying a Sieve agent token. Even an agent that somehow learns the URL gets `403`.
- **Other websites can't trick your browser into submitting it.** Sieve checks the request's `Origin` (or `Referer`) header against the page that served the form. A malicious site you happen to visit while Sieve is running cannot silently POST to the rotation endpoint.
- **Brute-forcing the current passphrase doesn't work.** After five wrong guesses in a row, the form locks itself for 15 minutes (`HTTP 423`, with a `Retry-After` header) and writes a single entry to the audit log so you can see that someone was probing. Further attempts during the cooldown are refused without producing more audit-log noise. The cooldown lives in memory — restarting Sieve clears it, but five fresh guesses will trigger it again.
- **Password managers don't save it.** The fields are tagged `autocomplete="new-password"` so your browser doesn't store them next to the admin-UI login credential.
- **Failures don't leak the typed values.** A failed submission redraws the form blank — Sieve never echoes the passphrase you typed back into the page, even on internal errors.

### If you forget your passphrase

There is no passphrase recovery. The encryption is real — anything that could "recover" your credentials without the passphrase would also let an attacker who got the database file do the same. Pick a passphrase you can remember, or store one in a password manager.

If you've forgotten it and need to start over, there's a controlled escape hatch:

```
$ sieve --reset-keyring

WARNING: --reset-keyring is destructive and irreversible.
  • 7 stored credential record(s) will be deleted.
  • You will need to re-add every connection (Gmail, OAuth
    accounts, LLM API keys, etc.) after running --setup again.
  • Policies, roles, tokens, audit history, and settings are
    preserved.

Type RESET (in capital letters) to confirm, anything else to abort: RESET

sieve: keyring reset. 7 credential record(s) deleted.
sieve: run with --setup to choose a new passphrase, then re-add your connections.
```

The flag deletes the encrypted credentials and the keyring metadata, and **only** those. Your policies, role-to-connection bindings, agent tokens, audit history, and settings all survive — so once you re-add the connections (using the same IDs), every existing token and binding starts working again without further changes.

The flag is a UX safeguard, not a security boundary: anyone with write access to `data/sieve.db` can already destroy the credentials by other means (`rm`, raw `sqlite3` deletes). The actual security boundary is file permissions on the database (`chmod 0600`, plus running Sieve as a dedicated user). The two safeguards `--reset-keyring` adds are:

- It refuses to run unless stdin is a TTY (no scripted accidental wipes).
- It requires the operator to type the literal string `RESET` (no muscle-memory `y` confirmations).

It also writes one audit-log entry recording the reset, which `rm` does not.

### Why rotation is fast

Sieve doesn't store your credentials encrypted under your passphrase directly. It stores each credential encrypted under a small per-record key, and that small key is encrypted under your passphrase. Rotation only re-encrypts the small keys; the credential payloads themselves are never touched.

That's why rotation completes in a few seconds even on installations with many connections, and why a failed rotation can never leave a credential in a half-encrypted state — the actual encrypted credentials don't change at all.

### What gets recorded

Every successful rotation writes one entry to the audit log with `operation = "keyring.rotate"`, the surface that drove it (`ui` or `cli`), and the count of credentials that were re-keyed. The entry is written inside the same database transaction as the rotation itself, so a failed rotation produces no audit row, and a successful rotation always has exactly one.

A `--reset-keyring` invocation produces a single `keyring.reset` audit entry recording the count of deleted credentials, written inside the same transaction as the deletes themselves.

No audit row ever contains the passphrase, any derived key, or any decrypted credential.

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
