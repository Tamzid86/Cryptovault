# Security Testing Report

Phase 5 of the CryptVault build. This covers static analysis, dependency scanning,
container image scanning, and dynamic (black-box) scanning, with real findings fixed
and verified by re-scanning — not just tool output pasted in. Raw reports are in
`docs/security-scans/`.

## Methodology

| Tool | Scope | What it checks |
|---|---|---|
| Bandit | `backend/app` | Python-specific insecure patterns (hardcoded secrets, `eval`, weak hashes, shell injection, etc.) |
| Semgrep | `backend/app`, `frontend/src` | Cross-language static analysis, community ruleset (OWASP-aligned) |
| pip-audit | `backend/requirements.txt` | Known CVEs in installed Python packages, against the PyPA advisory database |
| npm audit | `frontend/package.json` | Known CVEs in installed Node packages, against the npm advisory database |
| Trivy | `ev-backend`, `ev-frontend` Docker images | OS package CVEs, language-package CVEs, and embedded secrets in built container images |
| OWASP ZAP | Running backend, via `zap-api-scan.py` against `/openapi.json` | Active DAST: injection, misconfiguration, and information-disclosure classes, driven directly off the API's own schema |

Bandit and pip-audit run natively; **Semgrep has no native Windows binary** (its core
engine execs an OCaml binary that doesn't exist for `win32` — confirmed by hitting a
`FileNotFoundError` from the pip package's own launcher) and runs via its official Docker
image instead. Trivy and ZAP are Docker-native tools run the same way. Isolated from the
app's runtime venv in `backend/.venv-security` since semgrep's own dependency pins
conflict with FastAPI's.

## Summary

| Area | Before | After | Status |
|---|---|---|---|
| Bandit (backend) | 0 findings | — | Clean |
| Semgrep (backend + frontend) | 0 findings | — | Clean |
| pip-audit | 26 CVEs across 6 packages | 1 (no fix available) | Fixed 25/26 |
| npm audit | 5 CVEs (dev toolchain only) | 0 | Fixed 5/5 |
| Trivy — backend image | 52 HIGH/CRITICAL | 45 | Reduced; remainder is unpatched base-OS, not app-reachable |
| Trivy — frontend image | 70 HIGH/CRITICAL | 44 | Eliminated all dev-toolchain exposure; remainder is nginx base image |
| Trivy — secrets in either image | 0 | 0 | Clean |
| OWASP ZAP active scan | 116 pass / 2 warn / 0 fail | 118 pass / 0 warn / 0 fail | Fixed 2/2 |

## Findings and fixes

### 1. Dependency CVEs (pip-audit)

Initial scan found 26 known vulnerabilities:

| Package | Installed | CVEs | Fixed version |
|---|---|---|---|
| starlette | 0.38.6 | 7 | → 1.7.0 (via FastAPI 0.142.2) |
| cryptography | 43.0.1 | 6 | → 50.0.2 |
| python-multipart | 0.0.9 | 7 | → 0.0.32 |
| python-jose | 3.3.0 | 3 | → 3.5.0 |
| pyopenssl | 25.1.0 | 2 | → 26.4.0 |
| ecdsa | 0.19.2 | 1 | *(no fix — see below)* |

FastAPI itself was five minor versions behind (0.115.0 → 0.142.2), which meant starlette —
a transitive dependency FastAPI pins — was stuck on a version with multiple known issues.
Upgrading FastAPI pulled a compatible, patched starlette automatically. `pyopenssl` isn't a
direct dependency (it's pulled in by `webauthn`'s attestation-chain validation) and was
pinned explicitly in `requirements.txt` to force the fixed version, since `webauthn`'s own
spec doesn't require it.

This was a five-minor-version FastAPI jump and a starlette major version jump
(0.38 → 1.7) in one go. All 40 backend pytest cases and all 5 real-browser e2e scripts
were re-run afterward and passed with no changes needed to application code.

**Residual: `ecdsa` 0.19.2, CVE-2024-23342 (Minerva timing attack on P-256 signing).**
The `python-ecdsa` maintainers explicitly consider side-channel attacks out of scope and
have no planned fix. The attack requires actually calling `ecdsa.SigningKey.sign_digest()`;
verification is unaffected. `ecdsa` is installed because `python-jose` depends on it
unconditionally, but this project installs `python-jose[cryptography]` and only ever calls
`jwt.encode()`/`jwt.decode()` with `algorithm="HS256"` (HMAC, not ECDSA) — the vulnerable
code path is never executed. Accepted as a non-issue given actual usage, not blindly
waived because no fix exists.

### 2. Dependency CVEs (npm audit)

5 vulnerabilities (3 moderate, 1 high, 1 critical), all in the **dev-only** toolchain:
`esbuild` ≤0.24.2 (dev-server CORS issue — a malicious site could proxy requests through a
running `vite dev` server) and `@vitest/mocker` (path traversal), pulling in `vite` and
`vitest` as affected packages. None of these ship in the production build; they only run
locally during development and testing.

Fixed by upgrading `vite` 5.4.11 → 6.4.3 and `vitest` 2.1.8 → 4.1.11 (a major-version jump
for both). `@vitejs/plugin-react` stayed pinned at 4.3.4 — its peer range already covers
Vite 6, so no change was needed there. One test file referenced Node's `Buffer` global,
which vitest 4's type resolution no longer picked up implicitly; replaced with a plain-JS
equivalent rather than widening `tsconfig` types for one line. Build, all 12 unit tests,
and all 5 e2e scripts re-verified clean afterward.

(The project's earlier history already includes one specific near-miss here: Vite's
*bleeding-edge* line — the `create-vite` default at project scaffolding time — pulls an
experimental rolldown-based bundler with no working native binary on this Windows
environment. That's why `vite` and `vitest` are pinned to specific stable majors rather
than left on `latest`.)

### 3. Container image hardening (Trivy)

**Backend** (`python:3.12-slim` based): initial scan found 52 HIGH/CRITICAL findings — 51
in Debian base-OS packages (`util-linux` family, `login`, `ncurses`, `perl-base`,
`libsystemd0`, openssl libs) plus the same `ecdsa` CVE from pip-audit. The Dockerfile was
rewritten as a **multi-stage build**: `gcc` (needed only to compile wheels) no longer ships
in the final image, and an `apt-get upgrade` step pulls whatever Debian security patches
are available in the pinned snapshot. This dropped the base-image package count from 118 to
87 and the HIGH/CRITICAL count to 45.

Verified Debian's security repo *is* correctly configured in the base image
(`trixie-security` present in `/etc/apt/sources.list.d/debian.sources`) — the remaining 45
aren't a missing-repo misconfiguration, they're genuinely unpatched (yet) in this snapshot,
or are local-exec-class issues (e.g. `login`, `mount`) with no exposure through this
application: the app never shells out, never execs a subprocess, and exposes no local
access. Documented as accepted residual risk rather than something a Dockerfile can fix.

**Frontend** (was `node:20-alpine` running `npm run dev` directly): this surfaced the
real issue — the image shipped the *entire Node dev toolchain* in what should be a deployed
artifact. 70 HIGH/CRITICAL findings, including **44 CVEs in esbuild's embedded Go stdlib**,
duplicated across both a `linux-x64` *and* a `win32-x64` esbuild binary (both got bundled
because `node_modules` was copied wholesale from a Windows host checkout), plus CVEs in
npm's own vendored dependencies (`tar`, `cross-spawn`, `brace-expansion`, `minimatch`,
`glob`, `pacote`, `sigstore`, `ip-address`) — none of which are *this app's* dependencies at
all; they're npm's own internal tooling, shipped because the dev server was running inside
the container instead of a production build.

Fixed with a proper **multi-stage production build**: stage one runs `npm ci && npm run
build` to produce static assets, stage two serves them from `nginx:1.27-alpine` with no
Node, npm, or dev toolchain in the final image at all. This eliminated every one of those
70 findings outright — zero language-specific files detected in the rescanned image. The
previous single-stage Dockerfile is preserved as `Dockerfile.dev` for local
`docker-compose` development (hot reload), which `docker-compose.yml` now references
explicitly; the bare `Dockerfile` is the production build. The 44 remaining findings in the
rescanned image are nginx's own Alpine base libraries (`libssl3`, `libcrypto3`, `libxml2`,
`libpng`, `musl`, …) — the same "awaiting upstream" category as the backend's, not
something specific to this app.

Secret scanning (also part of Trivy's default scan) found **zero** embedded secrets in
either image.

### 4. Dynamic scanning (OWASP ZAP)

Ran `zap-api-scan.py` — ZAP's full active scanner driven directly from the backend's own
`/openapi.json`, rather than a generic crawl — against the running backend. This is the
right ZAP mode for a JSON API with no HTML to crawl.

First pass: **116 passed, 2 warnings, 0 failures**, out of every rule in ZAP's active rule
set — including every SQL injection variant (MySQL/MSSQL/PostgreSQL/Oracle/Hypersonic,
time-based and error-based), reflected/persistent/DOM-based XSS, SSTI (blind and
non-blind), XXE, path traversal, remote OS command injection, CRLF injection, LDAP/XPath
injection, Log4Shell, Spring4Shell, Shellshock, and the billion-laughs XML expansion
attack. All passed clean on the first run — the practical payoff of SQLAlchemy's
parameterized queries (no raw SQL string-building anywhere in the codebase) and Pydantic's
strict request validation on every endpoint.

The 2 warnings were both missing response headers: `X-Content-Type-Options` and
`Cross-Origin-Resource-Policy`. Fixed with a small middleware in `app/main.py` that sets
both on every response. Re-scan: **118 passed, 0 warnings, 0 failures.**

**Scope limitation, stated plainly:** this scan ran unauthenticated. ZAP exercised every
endpoint, but protected routes correctly returned 401 without a token rather than being
fuzzed with valid credentials behind them — confirming auth is enforced, but not a full
authenticated-traffic DAST pass (e.g. ZAP didn't attempt injection payloads *inside* an
authenticated file-sharing flow). A follow-up with ZAP's auth/session configuration wired
to a real login flow would extend coverage; not done here given time scope.

### 5. Static analysis (Bandit, Semgrep)

Both clean: 0 findings. Bandit scanned all 1,149 lines of `backend/app`. Semgrep ran 290
community rules against 29 backend files and 210 rules against 30 frontend files
(`--config auto`, no paid rule access). A clean static-analysis pass is a meaningful
*supporting* signal, not proof of absence of bugs — it means no common insecure pattern
matched, not that no vulnerability exists.

## OWASP Top 10 (2021) mapping

| Category | Status | Evidence |
|---|---|---|
| A01 Broken Access Control | Addressed | Per-file RBAC via `FileKeyShare.permission`; IDOR tests prove cross-user access returns 404 (`test_files.py`, `test_sharing.py`); owner-only actions return 403 when access exists but permission doesn't |
| A02 Cryptographic Failures | Addressed | E2E encryption is the project's core design — see `docs/` crypto notes (Phase 6); AES-256-GCM, X25519+HKDF, Argon2id, independent key derivations documented in `backend/app/core/security.py` |
| A03 Injection | Addressed | ZAP: all SQLi/XSS/SSTI/XXE/command-injection/CRLF classes passed; SQLAlchemy ORM used throughout, no raw SQL concatenation |
| A04 Insecure Design | Addressed | Two-step MFA flow designed around WebAuthn's challenge-response nature rather than bolted onto a single-call login (Phase 4); self-share-at-upload design for uniform access-control checks (Phase 2/3) |
| A05 Security Misconfiguration | Addressed | ZAP header findings fixed; CORS explicitly scoped (not wildcard with credentials); multi-stage Docker builds remove build tooling from runtime images |
| A06 Vulnerable Components | Addressed this phase | pip-audit/npm audit/Trivy run in this phase, 25/26 + 5/5 dependency CVEs fixed; residual items documented with justification, not ignored |
| A07 Identification & Auth Failures | Addressed | Argon2id password hashing, account lockout after repeated failures, rate limiting, TOTP + WebAuthn MFA, timing-safe login response for unknown emails |
| A08 Software/Data Integrity Failures | Addressed | Hash-chained audit log detects tampering (`services/audit.py`); AES-GCM authenticates every chunk (tamper → decrypt failure, proven in `crypto.test.ts`) |
| A09 Logging & Monitoring Failures | Partially addressed | Hash-chained audit log + per-login device fingerprinting with new-device flagging (Phase 4); no centralized log aggregation/alerting — out of scope for this project's size |
| A10 SSRF | Addressed | ZAP's SSRF-adjacent checks (external redirect, cloud metadata exposure) passed; no endpoint accepts a user-supplied URL for server-side fetching |

## OWASP ASVS (v4) — selected control mapping

| ASVS area | Control | Evidence |
|---|---|---|
| V2.1 Password Security | Argon2id, min length 12 | `core/security.py`, `schemas/auth.py` |
| V2.2 General Authenticator | TOTP (RFC 6238) + WebAuthn (FIDO2) as MFA | `api/v1/mfa.py`, verified against a real CDP virtual authenticator |
| V2.7 Out-of-Band Verifier | N/A | No SMS/email OTP in scope |
| V3.2 Session Binding | Short-lived JWT access tokens, separate longer-lived refresh tokens, distinct short-lived `mfa_pending` token type | `core/security.py` |
| V4.1 General Access Control | Per-resource authorization check on every file/share endpoint, not just route-level auth | `api/v1/files.py` |
| V4.2 Operation Level Access Control | 404 for no access, 403 for insufficient permission (deliberate distinction) | `_get_file_with_access`, `_require_owner_share` |
| V5.1 Input Validation | Pydantic schemas on every request body; base64 fields explicitly decoded/validated | `schemas/*.py` |
| V5.3 Output Encoding | React's default JSX escaping; no `dangerouslySetInnerHTML` anywhere in the frontend |
| V7.1 Log Content | Audit log records actor, action, target, IP, timestamp, hash-chained | `services/audit.py` |
| V9.1 Communications Security | TLS termination is a deployment concern, documented for Phase 6; CORS scoped to the actual frontend origin |
| V10.3 Deployed Application Integrity | Multi-stage builds, no build tooling in runtime images, Trivy-scanned; backend runs as an unprivileged user | This phase |
| V12.1 File Upload | Chunk size validated server-side against declared metadata; owner-only upload | `api/v1/files.py`, `test_files.py` |
| V14.2 Dependency Management | pip-audit + npm audit run and findings fixed this phase | This phase |

## Residual / accepted risks (consolidated)

- **`ecdsa` CVE-2024-23342** — unexploitable given HS256-only usage (see above).
- **Base-OS image CVEs** (Debian util-linux/login/ncurses family; Alpine's nginx-bundled
  libs) — not reachable through the application's own code paths; no shell-out, no local
  exec surface exposed via the API. A hardened production deployment would move to a
  distroless base image to eliminate this class entirely; not attempted here given the risk
  of silently breaking the C-extension-heavy dependencies (`cryptography`, `argon2-cffi`,
  `asyncpg`) without a shell available to debug it.
- **ZAP scan was unauthenticated** — confirms auth enforcement, not a full authenticated
  DAST pass. Noted above.
- **MFA-step failures don't count toward account lockout** (only password failures do) —
  carried over from Phase 4, noted here for completeness since it's an authentication
  control gap rather than purely a code-quality one.
- **Revoked share recipients keep offline access to an already-fetched file key** — the
  project's stated, deliberate scope limitation from Phase 3 (revocation removes future
  access, not already-retrieved plaintext).
