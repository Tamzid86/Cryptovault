# CryptVault

End-to-end encrypted file sharing. The server stores ciphertext and wrapped keys only —
it never sees plaintext files or private keys.

## Status

**Complete.** Phase 1 (auth core), Phase 2 (encrypted file upload/download), Phase 3
(sharing & access control), Phase 4 (MFA hardening: TOTP, WebAuthn/passkeys, login
activity), Phase 5 (security testing — scanning, OWASP Top 10/ASVS mapping), and Phase 6
(documentation — threat model, crypto rationale, attack/fix demo, limitations, TLS
deployment). Production hardening on top: server-side session revocation ("sign out
everywhere", plus revocation on every MFA change), a per-user storage quota, a strict
CSP, SPA deep-link routing in the nginx image, and a non-root backend container.

## Documentation

| Doc | Covers |
|---|---|
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE analysis — what's mitigated, what isn't, and why, with file-level evidence |
| [`docs/crypto-design.md`](docs/crypto-design.md) | The reasoning behind every cryptographic choice (X25519, AES-GCM, Argon2id×2, HKDF, JWT, nonce construction) |
| [`docs/attack-demo.md`](docs/attack-demo.md) | A real IDOR vulnerability deliberately reintroduced, exploited against a live instance, and fixed — plus a live AES-GCM nonce-reuse break |
| [`docs/limitations.md`](docs/limitations.md) | Honest accounting of what this design doesn't solve — forward secrecy, metadata leakage, trust in server-delivered JS, and more |
| [`docs/security-testing.md`](docs/security-testing.md) | Static/dependency/container/dynamic scan results, fixes applied, OWASP Top 10 / ASVS mapping |
| [`docs/deployment.md`](docs/deployment.md) | Production deployment with TLS (Caddy + Let's Encrypt, `docker-compose.prod.yml`) |

## Local development

Prereqs: Python 3.12, Node 20+, Docker.

```bash
# 1. Start Postgres (mapped to host port 55432 to avoid colliding with a native
#    Postgres install on 5432 -- see docker-compose.yml)
docker compose up -d postgres

# 2. Backend
cd backend
python -m venv .venv
.venv/Scripts/activate        # .venv/bin/activate on macOS/Linux
pip install -r requirements-test.txt
cp .env.example .env          # then set SECRET_ENCRYPTION_KEY (see Configuration notes)
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# 3. Frontend
cd frontend
npm install
npm run dev
```

Backend: http://localhost:8000/docs
Frontend: http://localhost:5173

## Testing

```bash
# Backend (register/login/lockout/audit-chain integrity, file CRUD + IDOR checks)
cd backend && pytest

# Frontend crypto (X25519/AES-GCM/HKDF round-trip + tamper/reuse tests)
cd frontend && npm test

# Real-browser smoke tests (needs both dev servers already running):
# auth flow; a 3-chunk file upload/download/delete with a sha256 check that
# the recovered file is byte-identical to the original; a two-user
# sharing/RBAC/revocation scenario; TOTP setup + MFA-gated login (with a
# hand-rolled RFC 6238 generator); and WebAuthn passkey registration + login
# via Chromium's CDP virtual authenticator (a real, if emulated, platform
# authenticator -- genuine attestation/assertion objects, real signature
# checks on the backend, including that an unenrolled authenticator is
# rejected); and silent access-token refresh (an injected 401 is recovered by
# one /auth/refresh + retry, and a rejected refresh token logs the user out);
# and surviving a page reload (httpOnly refresh cookie + non-extractable
# private key in IndexedDB, both cleared on logout); and key fingerprints
# (shown on the dashboard, verified before sharing, and a server-swapped key
# is flagged and blocked until explicitly accepted); and "sign out everywhere"
# (two browser contexts on one account: signing out on one ends the other's
# session too) plus the storage-quota readout updating after an upload.
cd frontend && npm run test:e2e
# Note: these scripts' combined login/register calls can exceed the
# backend's rate limiter (5 logins/min, 3 registers/min) if run back-to-back
# -- that's the limiter doing its job, not a bug. Restart the backend between
# runs, or run scripts individually, if you hit a 429.
```

## Security scanning

Full methodology, findings, fixes, and OWASP Top 10 / ASVS mapping:
[`docs/security-testing.md`](docs/security-testing.md). Raw tool output is in
`docs/security-scans/`.

```bash
# Static analysis (isolated venv -- bandit/pip-audit's pins would otherwise
# fight the app runtime's). Semgrep has no native Windows binary and runs via
# Docker instead (confirmed: its pip-package launcher execs a precompiled
# OCaml binary that isn't shipped for win32).
cd backend
python -m venv .venv-security
.venv-security/Scripts/pip install -r requirements-security.txt
.venv-security/Scripts/bandit -r app
.venv-security/Scripts/pip-audit
docker run --rm -v "$(pwd)/..":/src semgrep/semgrep semgrep --config auto /src/backend/app

# Frontend dependency scan
cd frontend && npm audit

# Container image scanning (build the images first: `docker compose build`,
# or `docker build ./backend` / `docker build ./frontend` directly)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity HIGH,CRITICAL ev-backend:latest
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity HIGH,CRITICAL ev-frontend:latest

# Dynamic/active scan against the running backend's own OpenAPI spec
docker run --rm zaproxy/zap-stable zap-api-scan.py -t http://host.docker.internal:8000/openapi.json -f openapi
```

## Architecture (quick reference)

- **Identity**: X25519 keypair generated client-side at registration. Private key is
  encrypted locally (AES-256-GCM, key derived via Argon2id from the user's password) and
  stored encrypted on the server — the server cannot decrypt it.
- **Files**: encrypted client-side with AES-256-GCM, a unique random key per file,
  chunked streaming (4 MiB chunks) with a counter-based per-chunk nonce. The server
  stores ciphertext bytes and nonces only; chunk content is never decrypted server-side.
- **Sharing**: the file key is wrapped to each recipient's X25519 public key
  (ECIES-style: ephemeral keypair + HKDF-SHA256). The uploader self-shares at upload time
  (a FileKeyShare row wrapped to their own public key, permission=`owner`) — the same
  mechanism later extends to other recipients. Revoking access deletes the wrapped-key
  row; the file ciphertext is never re-encrypted.
- **Access control**: every read (metadata, chunk download) requires a FileKeyShare row
  for the requesting user; a missing one returns 404, not 403, so probing file IDs can't
  distinguish "doesn't exist" from "not yours" (see `backend/tests/test_files.py` for the
  IDOR regression test). Owner-only actions (share, list shares, revoke, delete, upload)
  check the row's `permission`: no row is 404 (hidden existence), a `read`-only row is 403
  (seen but not permitted) — see `backend/tests/test_sharing.py`.
- **Audit log**: hash-chained (SHA-256) — tampering with or deleting a row breaks the
  chain for everything after it.
- **MFA**: TOTP (secret envelope-encrypted at rest under a server-only key, independent of
  the login password hash and the client-side KDF) and WebAuthn/passkeys (via `py_webauthn`
  + `@simplewebauthn/browser`). `/auth/login` resolves the password first; if either factor
  is configured it returns an `mfa_token` instead of real tokens, since a WebAuthn assertion
  is a challenge-response ceremony that can't be precomputed into a one-shot request the way
  a TOTP code can — see `LoginResult`'s docstring in `backend/app/schemas/auth.py`.
- **Login activity**: every login attempt is recorded with a device fingerprint; a
  first-time fingerprint is flagged `is_new_device` and surfaced on the Security page's
  activity feed — the practical stand-in for an email/push alert given this project has no
  mail infrastructure.
- **Session revocation**: every access and refresh token carries the account's
  `token_version`, checked on each request and on `/auth/refresh`. "Sign out everywhere"
  on the Security page (`POST /auth/logout-all`) bumps it and ends every session on every
  device. Enabling or disabling TOTP, or adding a passkey, bumps it too: other devices are
  signed out, and the session that made the change gets a fresh cookie.
- **Storage quota**: each account can own up to `max_storage_bytes_per_user` (1 GiB by
  default) of files, counted by declared plaintext size. Files shared *with* you count
  against their owner. Current usage is shown on the dashboard (`GET /users/me/storage`).
- **Account lockout & rate limiting**: 5 failed password attempts locks the account for 15
  minutes; login/register are separately rate-limited per IP (slowapi). MFA-step failures
  (wrong TOTP code, failed passkey assertion) do not themselves count toward lockout --
  documented as a scope limitation.

See `backend/app/core/security.py` and `frontend/src/crypto/` for the implementation. For
the reasoning behind each cryptographic choice, see `docs/crypto-design.md`; for what's
*not* covered by any of this, see `docs/limitations.md`.

## How CryptVault works, step by step

Every flow below runs in full on this codebase — these aren't aspirational descriptions,
they're what `backend/tests/` and `frontend/e2e/*.mjs` exercise and pass against. Exact
parameters (timeouts, key sizes, rate limits) are quoted from the actual config
(`backend/app/core/config.py`) so this stays accurate as the single source of truth rather
than two documents drifting apart.

### 1. Registration

1. The browser generates an X25519 keypair **locally** (`generateKeyPair`,
   `frontend/src/crypto/keys.ts`) — the private key never exists outside this page.
2. The browser generates a random 16-byte salt and runs the password through
   **Argon2id** (`iterations=3`, `memorySize=19 MiB`, via WASM — `deriveKeyWrappingKey`)
   to derive an AES-256-GCM **key-wrapping key**. This is a *client-side-only* derivation,
   separate from anything the server ever computes.
3. The browser encrypts the private key under that wrapping key (`encryptPrivateKey`) —
   fresh random 12-byte nonce, AES-256-GCM.
4. The browser `POST /auth/register`s: email, password (plaintext, protected only by TLS
   in production — see `docs/deployment.md`), the **public** key, and the three
   ciphertext/salt/nonce blobs from steps 2–3, all base64.
5. The server hashes the password with a **second, independent** Argon2id call
   (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=4` — `core/security.py`,
   `hash_password`) for login verification, and stores: email, that hash, the public key,
   and the three ciphertext blobs as opaque bytes it never decodes or interprets.
6. An audit log entry (`user.register`) is appended to the hash chain.

**Security guaranteed here:** the plaintext password is used once, transiently, to derive
two things in two different places (server-side login hash; client-side wrapping key) that
can never be computed from one another. The server ends this flow holding a password hash
it can verify against but not invert, and a private-key ciphertext it has no key for —
even a complete database dump reveals neither the password nor the private key (see
`docs/crypto-design.md` for why these two Argon2id calls must never be merged).

### 2. Login — no second factor configured

1. `POST /auth/login` with email + password.
2. The server looks up the user. **Whether or not one is found**, it runs an Argon2id
   comparison — against the real hash if found, against a fixed dummy hash if not — so a
   timing side-channel can't reveal account existence (`api/v1/auth.py`).
3. Wrong password: `failed_login_attempts` increments; at **5** it locks the account for
   **15 minutes** (`failed_login_lockout_threshold` / `lockout_duration_minutes`); a failed
   `LoginEvent` and an `auth.login_failed` audit entry are recorded regardless of whether
   lockout triggered.
4. Correct password, account not locked, no TOTP/passkey registered: the server resets the
   failure counter, computes a device fingerprint (`SHA256(user_agent|ip)`,
   `services/login.py`), checks whether a *prior successful* login shares that fingerprint
   to decide `is_new_device`, records the `LoginEvent`, appends an `auth.login_succeeded`
   audit entry, and issues a **15-minute access token** + **7-day refresh token** (JWT,
   HS256) plus the stored `key_bundle` (public key, encrypted private key, salt, nonce).
5. The browser re-derives the wrapping key from the password it already has in memory plus
   the salt just received, decrypts the private key client-side, and holds the **access
   token and decrypted private key in JS memory only** — never `localStorage` or a cookie
   (`frontend/src/api/client.ts`). A page refresh wipes this by design; see
   `docs/limitations.md` for the trade-off.

**Security guaranteed here:** `/auth/login` is rate-limited to **5 requests/minute per
IP** (slowapi); an attacker gets at most 5 password guesses a minute *and* at most 5 total
before lockout, whichever comes first. The private key is never transmitted in decrypted
form at any point in this exchange.

### 3. Login — TOTP configured

1. Steps 1–3 above are identical. At step 4, the server instead finds `totp_enabled=true`
   and returns `{mfa_required: true, methods: ["totp"], mfa_token}` — **no real tokens
   yet**. `mfa_token` is a distinct JWT type (`"mfa_pending"`, 5-minute expiry —
   `mfa_token_expire_minutes`) that proves only "this subject's password checked out,"
   nothing more; every endpoint that accepts one checks that `type` field explicitly
   (`resolve_mfa_user`) so it can never be mistaken for a full access token.
2. The browser prompts for a 6-digit code and `POST /auth/login/mfa/totp` with
   `{mfa_token, code}`.
3. The server resolves the `mfa_token`, decrypts the user's TOTP secret (envelope
   decryption under `secret_encryption_key`, independent of the JWT secret and the
   password hash — `decrypt_secret`), and verifies the code with a ±1 time-step window
   (`pyotp`, 30-second steps). Only on success does it run the same token-issuance +
   login-event + audit path as step 4 above.

**Security guaranteed here:** a stolen password alone is insufficient — a correct password
only earns a 5-minute window to *also* produce a valid code from the physical authenticator
app. The TOTP secret itself is never transmitted again after the one-time setup QR code.

### 4. Login — passkey (WebAuthn) configured

1. Same as TOTP's step 1, except `methods` includes `"webauthn"`.
2. The browser calls `POST /auth/webauthn/login/options` with the `mfa_token`. The server
   generates a random challenge scoped to this user's registered credential IDs, stores it
   with a timestamp (5-minute TTL — `_WEBAUTHN_CHALLENGE_TTL`), and returns WebAuthn's
   standard options JSON.
3. `@simplewebauthn/browser`'s `startAuthentication` calls the browser's native
   `navigator.credentials.get()`, which prompts the platform authenticator (fingerprint,
   face, PIN, security key) and — critically — **cryptographically binds the resulting
   assertion to the origin that requested it**, entirely inside the browser, before any
   JavaScript on the page (trusted or not) sees the result.
4. `POST /auth/webauthn/login/verify` with `{mfa_token, credential}`. The server verifies
   the assertion's signature against the stored public key, checks the challenge hasn't
   expired, and checks the authenticator's `sign_count` has increased since last use (a
   regression can indicate a cloned authenticator). On success: same token issuance as
   above.

**Security guaranteed here:** a phishing site at a look-alike domain cannot obtain a valid
assertion for this one, full stop — the browser itself refuses to produce one for the
wrong origin, so there's no "the user got tricked" failure mode the way there is with a
TOTP code someone can be talked into typing into a fake page. Verified against a real (if
emulated) authenticator in `e2e/webauthn-smoke.mjs`, including that an *unenrolled*
authenticator is correctly rejected.

### 5. Uploading a file

1. The browser generates a **fresh random 256-bit AES key for this one file**
   (`generateFileKey`) — never reused across files, never derived from anything.
2. The filename is encrypted under that key with its own random nonce
   (`encryptChunk` on the UTF-8 filename bytes) — the server never sees it in plaintext
   either.
3. The file is sliced into **4 MiB chunks** (`max_chunk_size_bytes`). A random 4-byte
   prefix is generated once for this file; each chunk's 12-byte nonce is
   `prefix || big-endian chunk index` (`chunkNonce`) — deterministically unique as long as
   chunk indices don't repeat, which the upload loop guarantees by construction. (See
   `docs/attack-demo.md` for a live demonstration of exactly what goes wrong if a nonce
   *is* reused, and why this construction avoids it structurally rather than
   probabilistically.)
4. The uploader wraps the file key to **their own** public key (ECIES: fresh ephemeral
   X25519 keypair, HKDF-SHA256 over the shared secret, AES-256-GCM wrap — `wrapFileKey`).
   This is the "self-share" that makes the uploader's own future access go through the
   exact same check as anyone else's.
5. `POST /files` sends the encrypted filename/nonce, chunk metadata, and the wrapped key.
   The server validates `chunk_size <= max_chunk_size_bytes`, creates the `FileObject` row
   and a `FileKeyShare(permission=owner)` row, and logs `file.create`.
6. Each encrypted chunk is `PUT /files/{id}/chunks/{i}` with its nonce in an
   `X-Chunk-Nonce` header. The server checks the caller owns the file, checks the chunk
   index is in range, checks the ciphertext isn't larger than the declared chunk size plus
   the 16-byte GCM tag, and writes the bytes to disk off the event loop
   (`run_in_threadpool`) — the server at no point decrypts or needs to decrypt anything.

**Security guaranteed here:** plaintext file content and the filename never leave the
browser unencrypted. A compromise of one file's key exposes exactly that one file, nothing
else — there's no master key whose compromise cascades.

### 6. Listing and downloading files

1. `GET /files` joins `FileObject` with `FileKeyShare` filtered to the current user —
   returning only files they have *some* access to (owner or recipient), each with
   *their own* wrapped copy of that file's key.
2. For each file, the browser unwraps the key with its own private key
   (`unwrapFileKeyForSummary`) and decrypts the filename for display.
3. On download, each chunk is fetched via `GET /files/{id}/chunks/{i}`. The server's
   **single shared access check** (`_get_file_with_access`) requires a `FileKeyShare` row
   for this exact user; anything else is **404, not 403** — a user with no access can't
   even confirm the file exists. (This exact check is the subject of
   `docs/attack-demo.md`'s live exploit-and-fix demonstration.)
4. Each chunk is decrypted and its GCM authentication tag verified as part of decryption
   (`decryptChunk`); any tampering — in transit, on disk, or a bug — makes decryption throw
   rather than silently returning corrupted bytes, and the whole download aborts on the
   first bad chunk rather than assembling a partially-tampered file.
5. Verified chunks are reassembled into a `Blob` and handed to the browser's native
   download flow.

**Security guaranteed here:** every single byte returned to the browser has already passed
an authenticated-encryption integrity check by the time it's used; the server is
structurally incapable of serving a file to someone without a provable grant of access to
it, because that grant *is* what makes the content decryptable at all.

### 7. Sharing a file with another user

1. The owner enters a recipient's email. The browser calls `GET /users/lookup` (requires
   auth) to get that email's public key.
2. The browser unwraps **its own** copy of the file key, then wraps a **fresh** copy of
   that same key to the recipient's public key — new ephemeral X25519 keypair, new HKDF
   derivation, new nonce; nothing is reused from the owner's own wrap.
3. `POST /files/{id}/shares` sends the recipient's email and the new wrapped-key material.
   The server checks the caller actually holds `permission=owner` on this file (`
   _require_owner_share`), rejects sharing with oneself, rejects an unknown recipient
   email, rejects a recipient who already has a share, creates a
   `FileKeyShare(permission=read)` row, and logs `file.share.create`.
4. The recipient's next `/files` call includes the file, with their own wrapped key.

**Security guaranteed here:** a `read`-permission holder cannot reach this endpoint at all
for someone else's grant (403 — they're known to exist for this file but not permitted);
someone with zero relationship to the file gets 404 (existence hidden). Both are tested in
`backend/tests/test_sharing.py`.

### 8. Revoking access

1. The owner selects a recipient to remove. `DELETE /files/{id}/shares/{recipient_id}`.
2. The server re-checks owner permission, explicitly refuses to let the owner revoke
   *their own* `permission=owner` row (which would orphan the file), deletes the
   recipient's `FileKeyShare` row, and logs `file.share.revoke`.
3. The recipient's next `/files` call (after their own next login, since sessions are
   memory-only — see step 2) no longer includes the file; a subsequent chunk-download
   attempt gets 404.

**Security guaranteed here — and its explicit limit:** this removes *future* access
cleanly; it does **not** retroactively invalidate a key the recipient already fetched and
could have saved locally before revocation. True revocation of already-distributed key
material would need re-encrypting the file under a new key for every *remaining*
authorized party — not implemented, and said so plainly in `docs/limitations.md` rather
than implied to work.

### 9. Setting up TOTP

1. `POST /auth/totp/setup` (authenticated): the server generates a random base32 secret,
   builds the `otpauth://` URI, renders a QR code **server-side** (`qrcode` + Pillow), and
   stores the secret **envelope-encrypted** (AES-256-GCM under `secret_encryption_key`) —
   but leaves `totp_enabled=false`.
2. The user scans the QR (or enters the secret manually) in their authenticator app.
3. `POST /auth/totp/verify {code}`: only a **correct** code flips `totp_enabled=true` and
   logs `mfa.totp_enabled`. An abandoned setup — QR shown, never confirmed — never silently
   turns on a 2FA requirement for a code the user never actually captured.
4. `POST /auth/totp/disable` requires **re-entering the password**, not just a valid
   session token — a stolen-but-short-lived access token can't silently strip 2FA from an
   account on its own.

### 10. Registering a passkey

1. `POST /auth/webauthn/register/options` (authenticated): a fresh challenge, excluding
   any already-registered credential IDs for this user (so the same authenticator can't be
   registered twice).
2. `startRegistration` triggers `navigator.credentials.create()` — the authenticator
   produces an attestation bound to this origin and challenge.
3. `POST /auth/webauthn/register/verify {credential}`: the server checks the challenge
   hasn't expired (5 minutes), cryptographically verifies the attestation, and stores the
   credential's public key and starting `sign_count`. Logged as `mfa.webauthn_registered`.

### 11. Every security-relevant action: the audit log

`register`, `login_succeeded`/`login_failed`, `file.create`/`delete`,
`file.share.create`/`revoke`, `mfa.totp_enabled`/`disabled`, `mfa.webauthn_registered` —
every one of these appends a row where
`entry_hash = SHA256(prev_hash || actor_id || action || target_type || target_id ||
timestamp)` (`services/audit.py`). Editing or deleting **any** row breaks `entry_hash`/
`prev_hash` continuity for every row after it; `verify_chain()` walks the whole table and
catches it. This doesn't prevent tampering by someone with direct database access — it
makes that tampering **detectable after the fact**, which a plain append-only table
without chaining would not.

### 12. New-device detection

Every login attempt — successful or not — computes `device_fingerprint =
SHA256(user_agent|ip)`. If no *prior successful* login for this user shares that exact
fingerprint, the attempt is flagged `is_new_device = true` and stored on the `LoginEvent`
row. The Security page's activity feed (`GET /users/me/login-events`) surfaces the last 20
of these, new-device ones visually distinguished — the practical, in-app stand-in for an
email/push alert, since this project has no mail infrastructure (see
`docs/limitations.md`).

## Configuration notes

- `backend/.env`'s `secret_encryption_key` is **required** — there is no default, so the
  backend won't start until it's set. It must be a base64-encoded 32-byte value (generate
  with `python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"`).
  It envelope-encrypts TOTP secrets at rest and is independent of `jwt_secret` and the
  password hash — never reuse one for another.
- A real deployment also needs `webauthn_rp_id`/`webauthn_origin` set to the actual domain;
  the `localhost` defaults only work for local development. Full production setup with TLS:
  [`docs/deployment.md`](docs/deployment.md).
