# Threat Model (STRIDE)

## System overview

```
┌─────────────┐   HTTPS (prod) / HTTP (dev)   ┌──────────────┐      ┌────────────┐
│   Browser   │ ─────────────────────────────▶│   FastAPI    │─────▶│  Postgres  │
│ (React SPA, │◀───────────────────────────── │   backend    │◀─────│            │
│  crypto in  │   JSON + encrypted chunks      │              │      └────────────┘
│  JS memory) │                                │              │─────▶┌────────────┐
└─────────────┘                                └──────────────┘      │ chunk store│
       ▲                                                              │(filesystem)│
       │ serves the SPA's JS/CSS/HTML itself                          └────────────┘
       └──────────────────────── nginx (production) / Vite dev server
```

**Trust boundaries**, in order of how much a compromise there costs:

1. **Browser ↔ backend**, over the network. Crosses an untrusted network in production;
   TLS is the only thing holding this boundary (see `docs/deployment.md`).
2. **Backend ↔ Postgres / chunk storage**, assumed trusted (same deployment, not
   independently hardened in this project's scope).
3. **Whoever serves the frontend's JS ↔ the browser.** This is the boundary this
   project's whole design is honest about *not* fully solving — see
   [`docs/limitations.md`](limitations.md#trust-in-the-server-delivered-javascript). The
   server that serves `index.html`/the JS bundle could serve a modified bundle that
   exfiltrates plaintext or keys, and nothing in this architecture detects that.

**Assets, roughly in order of what a compromise costs the user:**

- File plaintext (never transmitted or stored — the asset the whole system protects)
- User X25519 private keys (password-encrypted at rest on the server; once unlocked in the browser, held only as a non-extractable WebCrypto key — in memory and in IndexedDB so a reload can resume the session)
- Per-file symmetric keys (exist only wrapped, per recipient, server-side)
- Account passwords (hashed, never stored or logged in plaintext)
- TOTP secrets (envelope-encrypted at rest)
- Session tokens (JWT access/refresh, bearer — see Spoofing below)
- Audit log integrity (doesn't protect a secret, but protects the ability to *detect*
  tampering with everything else)

## Spoofing

| Threat | Mitigation |
|---|---|
| Credential stuffing / password guessing | Argon2id hashing (`core/security.py`); account lockout after 5 failed attempts for 15 min (`settings.failed_login_lockout_threshold`/`lockout_duration_minutes`); rate limiting on `/auth/login` (5/min/IP) and `/auth/register` (3/min/IP) via slowapi |
| Login with password alone when MFA is enabled | `/auth/login` returns `mfa_required` + a short-lived `mfa_token` instead of real tokens whenever TOTP or a passkey is configured — password alone never completes login (`api/v1/auth.py`) |
| Stolen/XSS'd token used to impersonate a session | The 15-min access token is kept in JS memory only, never `localStorage` (`frontend/src/api/client.ts`). The 7-day refresh token never reaches JS at all: it's an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to `/api/v1/auth` (`set_refresh_cookie` in `services/login.py`), rotated on every refresh, cleared by `/auth/logout`. XSS can still act *as* the user while the page is open, but can't carry the refresh token away. A strict production CSP (`frontend/nginx.conf`) blocks inline/injected script and limits `connect-src` to the app's own origin. Every token carries the account's `token_version` (`models/user.py`), checked in `get_current_user` and `/auth/refresh`. "Sign out everywhere" (`/auth/logout-all`) and any MFA change (TOTP enabled or disabled, passkey added) bump it, so a token copied off the machine can be killed before it expires (`test_logout_all_revokes_every_copy_of_the_session`, `test_enabling_totp_revokes_earlier_tokens_but_keeps_this_session`) |
| WebAuthn phishing (fake site relays a real assertion) | Structurally prevented by the protocol itself: the browser binds the assertion to the origin that requested it, and verification checks `expected_origin`/`expected_rp_id` (`api/v1/mfa.py`) — a phishing site at a different origin simply cannot obtain a valid assertion for this RP |
| Account enumeration via timing on `/auth/login` | A dummy Argon2id hash is compared for unknown emails so response timing doesn't distinguish "wrong password" from "no such account" (`api/v1/auth.py`) |
| Account enumeration via `/users/lookup` | **Not mitigated** — any authenticated user can confirm whether an email has an account, by design, since share-by-email needs this. Documented trade-off, not an oversight — see `limitations.md` |

## Tampering

| Threat | Mitigation |
|---|---|
| Ciphertext modified in transit or at rest (DB, disk) | AES-256-GCM's authentication tag detects any modification; decryption throws rather than returning corrupted plaintext (proven in `frontend/src/crypto/crypto.test.ts`'s tamper test, and exercised live by `download.ts`, which aborts the whole download on the first failed chunk) |
| Audit log edited to remove evidence | SHA-256 hash chain (`services/audit.py`) — modifying or deleting any entry breaks `entry_hash`/`prev_hash` continuity for every entry after it, detectable via `verify_chain()`. Appends are serialized with a Postgres advisory lock so concurrent requests can't fork the chain (which `verify_chain()` would otherwise misreport as tampering) |
| JWT modified to escalate privilege or impersonate another subject | HMAC-signed (HS256) under a server-only secret; `python-jose` rejects any signature mismatch |
| MITM tampers with requests/responses (e.g. swaps a recipient's public key mid-share) | TLS in production is the actual control here (see `deployment.md`) — local dev runs plain HTTP, which is why this matters for the deployment doc, not just a nice-to-have |
| A malicious or compromised *server* answers a recipient lookup with its own public key, so the shared file key is wrapped to the server (TLS doesn't help here — the server is the attacker) | **Detectable, not prevented.** Sharing is two-step (`frontend/src/files/share.ts`): the sender is shown the recipient's key fingerprint (first 128 bits of SHA-256, `crypto/fingerprint.ts`) before confirming, and every user's dashboard shows their own — comparing the two out of band catches a swap. The browser also pins each contact's fingerprint on first share (trust on first use, `auth/keyStore.ts`); a later lookup returning a different key is flagged as a likely interception and sharing is blocked until the sender explicitly confirms. Limits: a swap on the *very first* share is only caught if the users actually compare fingerprints; pins are per browser; and all of this assumes the JavaScript itself is honest (see "Trust in the server-delivered JavaScript" in `limitations.md`). Exercised by `frontend/e2e/fingerprint-smoke.mjs` |
| Replaying an *old, previously-valid* ciphertext for a chunk slot | **Only partially mitigated.** AES-GCM's tag proves a given ciphertext is authentic *for that nonce*, not that it's the *current* version of chunk N — if chunk 3 were overwritten and then an attacker (with DB/disk write access) restored the old row, it would still decrypt and verify successfully. Defending against this needs a higher-level integrity mechanism (e.g. a signed manifest covering the whole file) that this project doesn't implement; the practical exposure is small since it requires DB/disk write access, which is a much larger compromise already |

## Repudiation

| Threat | Mitigation |
|---|---|
| A user denies performing a sensitive action (sharing a file, disabling 2FA) | Every security-relevant action is recorded in the hash-chained audit log with actor, action, target, IP, and timestamp: `user.register`, `auth.login_succeeded`/`login_failed`, `file.create`/`delete`, `file.share.create`/`revoke`, `auth.mfa_failed`, `mfa.totp_enabled`/`disabled`, `mfa.webauthn_registered` (grep `audit.append_entry` across `api/v1/*.py`) |
| Compromised credentials used to perform actions "as" the real user | **Not mitigated beyond the above.** A bearer-token system without hardware-bound proof-of-presence can record *which account* did something, never *which human*. WebAuthn narrows this for login itself (a passkey is bound to a physical authenticator) but doesn't extend to every subsequent action in the session |

## Information Disclosure

| Threat | Mitigation |
|---|---|
| Server operator reads file plaintext | Core design: plaintext never reaches the server. Chunks are AES-256-GCM ciphertext end to end; filenames are encrypted too (`encrypted_filename`), not just content |
| Server operator reads a user's private key | Encrypted client-side before it's ever sent (`encrypted_private_key`); the server only ever stores ciphertext and cannot derive the wrapping key (that requires the user's password, which the server never receives in a usable form for this purpose — see `crypto-design.md`) |
| TOTP secret theft from a DB dump | Envelope-encrypted at rest under `secret_encryption_key`, a server-only key independent of both the password hash and the JWT secret (`core/security.py`) |
| File metadata — size, chunk count, upload time, who-shares-with-whom — visible to the server | **Not mitigated.** Necessarily visible: the server needs `size_bytes`/`chunk_size`/`num_chunks` to serve chunks at all, and the `FileKeyShare` table *is* the sharing graph. Documented in `limitations.md`, not hidden |
| IDOR — accessing another user's file/chunks by ID | Every read requires a `FileKeyShare` row for the requesting user (`_get_file_with_access` in `api/v1/files.py`); missing access returns 404, not 403, so it can't even be used to confirm a file's *existence*. **This is the subject of the attack/fix demonstration in `docs/attack-demo.md`.** |
| Verbose error messages leaking internals | FastAPI's default production error handling doesn't leak tracebacks; `HTTPException` details are deliberately generic ("Invalid email or password", "File not found") rather than exposing why. ZAP's `Application Error Disclosure` [90022] check passed clean (`security-testing.md`) |

## Denial of Service

| Threat | Mitigation |
|---|---|
| Credential-stuffing / brute-force traffic | Rate limiting (slowapi) on `/auth/login`, `/auth/register`, and the MFA-completion endpoints (5/min/IP) |
| **Lockout used as a DoS against a known victim** | Not mitigated — an attacker who knows a target's email can deliberately fail their password 5 times to lock them out for 15 minutes. This is the standard, generally-accepted trade-off of any lockout policy (the alternative is unlimited password guessing); noted here rather than left implicit |
| Unbounded storage consumption by an authenticated user | Mitigated per account. Per-chunk size is capped (4 MiB, `max_chunk_size_bytes`). `create_file` requires `num_chunks` to match `size_bytes`, and rejects a file that would push the owner's total declared size past `max_storage_bytes_per_user` (1 GiB default, 413), under a row lock so parallel uploads can't race past it. `upload_chunk` caps each chunk at its share of the declared size plus the 16-byte GCM tag, so bytes on disk can't exceed what the quota counted. Shared files count against the owner only (`test_storage_quota_is_enforced_and_reported`, `test_quota_counts_only_owned_files_not_shared_ones`). Open registration means many accounts give many quotas (see `limitations.md`) |
| TOTP code brute-forcing | Rate-limited the same as login (5/min/IP), and failed MFA-step codes count toward the same account lockout as failed passwords (`record_failed_attempt` in `services/login.py`). The lockout is re-checked on every MFA endpoint via `resolve_mfa_user`, so a pending `mfa_token` stops working once the account locks — spreading guesses across many IPs doesn't get past 5 attempts per 15 minutes |
| TOTP code replay (shoulder-surfed or phished code reused) | The time-step of the last accepted code is stored (`users.totp_last_used_step`), and login only accepts a code for a strictly later step — a code works once, not for the ~90 s its validity window would otherwise allow |

## Elevation of Privilege

| Threat | Mitigation |
|---|---|
| A `read`-permission recipient performs owner-only actions (delete, share, revoke, overwrite chunks) | RBAC checked per-endpoint against `FileKeyShare.permission`, not just route-level auth: `_require_owner_share` for share management; `delete_file`/`upload_chunk` check `FileObject.owner_id == user.id` directly. Covered by `test_sharing.py::test_non_owner_cannot_share_file_with_others`, `test_read_recipient_cannot_list_or_revoke_shares`, `test_shared_recipient_cannot_delete_or_upload_to_file` |
| Hijacked session used to strip the account's own MFA | `/auth/totp/disable` requires re-entering the password, not just a valid access token (`api/v1/mfa.py`) — a short-lived stolen token alone can't turn off 2FA |
| Orphaning a file by revoking its owner's own access | `revoke_share` explicitly rejects revoking a `permission=owner` row (`api/v1/files.py`), tested in `test_sharing.py::test_cannot_revoke_owner_share` |

## What this document doesn't cover

Cross-cutting design trade-offs that don't map cleanly to one STRIDE category — lack of
forward secrecy, trust in the server-delivered JavaScript, metadata leakage as a *pattern*
rather than a single threat — are consolidated in [`docs/limitations.md`](limitations.md)
instead of being split across six tables here.
