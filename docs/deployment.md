# Deployment & TLS

Everything up to this point has run over plain HTTP on `localhost` — fine for
development, but several of this project's own controls depend on TLS actually being
present in production: the threat model's Tampering section names a MITM altering
share requests in transit as a real threat whose *only* mitigation is TLS; WebAuthn's
`expected_origin` check requires `https://` in any non-`localhost` deployment (browsers
refuse WebAuthn over plain HTTP outside `localhost`); and cookies/headers security
generally assumes a secure transport underneath it.

This hasn't been exercised against a real public domain in this environment (no domain or
public host available) — `docker-compose.prod.yml` and `Caddyfile` are both
**syntax-validated** (`docker compose config`, `caddy validate`), not live-deployment-tested.
What's documented below is a complete, working configuration, not a sketch.

## What changes between dev and production

| | Local dev (`docker-compose.yml`) | Production (`docker-compose.prod.yml`) |
|---|---|---|
| Frontend | `Dockerfile.dev` — Vite dev server, hot reload | `Dockerfile` — static build served by nginx |
| TLS | None (plain HTTP) | Caddy, automatic via Let's Encrypt |
| Backend/frontend ports | Published directly (`8000`, `5173`) | Not published at all — only Caddy is reachable from outside |
| Secrets | Defaults baked into `backend/.env` (fine for a throwaway local Postgres) | Required, no defaults — compose fails fast via `${VAR:?message}` if unset |
| `webauthn_rp_id`/`webauthn_origin`/`cors_origins` | `localhost` | Real domain, `https://` |

## Deploying

1. **Point DNS at the host** and ensure ports 80 and 443 are reachable from the internet —
   Caddy needs port 80 for the ACME HTTP-01 challenge even though the end result serves
   everything over 443.

2. **Generate real secrets** and write them to `.env.prod` (copy `.env.prod.example` as a
   starting point — that file is safe to commit; `.env.prod` itself is gitignored):

   ```bash
   cp .env.prod.example .env.prod
   python -c "import secrets; print(secrets.token_urlsafe(32))"      # -> JWT_SECRET
   python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"  # -> SECRET_ENCRYPTION_KEY
   # generate a real Postgres password too -- don't ship the example's
   ```

   Edit `.env.prod` with: `DOMAIN` (your real domain), `POSTGRES_PASSWORD`, `JWT_SECRET`,
   `SECRET_ENCRYPTION_KEY`. Every one of these is independent on purpose — see
   `crypto-design.md`'s point about not deriving multiple secrets from one "app secret."

3. **Build and start:**

   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
   ```

4. **Run migrations** (the backend image doesn't run them automatically on start, to keep
   container startup from racing a migration against multiple replicas):

   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.prod exec backend alembic upgrade head
   ```

5. Caddy obtains a certificate for `DOMAIN` automatically on first request and renews it
   in the background indefinitely — no cron job, no certbot, no manual renewal step.

**Upgrading a deployment that predates the non-root backend image:** the backend now runs
as an unprivileged `app` user (uid 10001). A `file_storage` volume created by an older
image is owned by root, so the new container can't write chunks to it until you change its
owner, once:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod run --rm --user root backend chown -R app:app /app/data
```

Then run the migrations (step 4). The `token_version` migration signs everyone out once,
because tokens issued before it carry no version.

### Trying the production stack locally

Set `DOMAIN=localhost` in a scratch env file. Caddy then serves `https://localhost` from
its own local CA instead of Let's Encrypt, and WebAuthn accepts `localhost` as an RP ID.
`E2E_BASE_URL=https://localhost node e2e/sessions-smoke.mjs` (from `frontend/`) drives
that stack in a real browser, under the production CSP. Use a separate project name
(`docker compose -p cvprod ...`) so it doesn't replace the dev `postgres` container.

## What Caddy does for you

The `Caddyfile` routes `/api/*`, `/docs`, and `/openapi.json` to the backend container and
everything else to the frontend's nginx, all over one domain (avoids CORS entirely for the
app's own traffic — `CORS_ORIGINS` only matters for the rare case of a different origin
calling the API directly). It also sets `Strict-Transport-Security`, telling browsers to
never attempt a plain-HTTP connection to this domain again after the first successful
HTTPS one. This is additive to, not a replacement for, the backend's own security headers
middleware (`X-Content-Type-Options`, `Cross-Origin-Resource-Policy` — `app/main.py`,
added in response to the ZAP findings in `security-testing.md`).

## What the frontend container does

`frontend/nginx.conf` serves the built SPA:

- **Client-side routes fall back to `index.html`.** Reloading `/dashboard` or opening a
  link to `/security` reaches React Router instead of nginx's 404.
- **A strict Content-Security-Policy:** scripts only from the app's own origin (plus
  `'wasm-unsafe-eval'` for the Argon2id WASM), no inline script, and `connect-src 'self'`.
  Also `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and a restrictive
  `Permissions-Policy`.
- **Caching:** hashed `/assets/*` files are cached as immutable, and `index.html` is
  `no-cache`, so a new deploy is picked up on the next load.

The bundle is built with `VITE_API_BASE_URL=/api/v1` (a build arg in `frontend/Dockerfile`),
so the browser calls the API on the same origin through Caddy.

## Operational notes not covered by the compose file

- **Database backups.** `docker-compose.prod.yml` persists Postgres data in a named
  volume, which survives container recreation but not host loss. A real deployment needs
  `pg_dump` on a schedule, shipped somewhere other than the same host (S3, another
  machine) — not set up here, since it depends entirely on where this is actually hosted.
- **Chunk storage backup.** Same caveat for the `file_storage` volume — it holds every
  encrypted chunk. Back it up with the same seriousness as the database; losing it loses
  user files as completely as the users losing their passwords would (see
  `limitations.md`).
- **Postgres and chunk storage are not externally reachable** in this compose file by
  design (no published ports) — only Caddy is. If you need direct DB access for
  maintenance, use `docker compose exec postgres psql` rather than publishing 5432.
- **Horizontal scaling isn't addressed.** The backend is stateless aside from the
  rate-limiter's in-memory counters (`slowapi` — see `core/rate_limit.py`), which means
  running multiple backend replicas behind Caddy would give each replica its own
  independent rate-limit state rather than a shared one. Fine for one instance; something
  to fix (a Redis-backed limiter) before scaling beyond it.
