# Cryptographic Design

The one design principle everything else follows from: **the server should be able to
lose a complete copy of its database and filesystem to an attacker without that attacker
recovering a single byte of plaintext or a single usable private key.** Every choice below
is in service of that, including the choices that *don't* fully achieve it — those are
called out as such, not hidden.

## Identity: X25519 keypairs

Each user gets an X25519 keypair generated **in the browser** at registration
(`frontend/src/crypto/keys.ts`, via `@noble/curves`). X25519 (Curve25519 for Diffie-Hellman)
rather than RSA or P-256 NIST curves, for three concrete reasons:

- **It's a pure key-agreement primitive**, which is all this project needs identity keys
  for (wrapping/unwrapping file keys via ECIES — see Sharing below). RSA would work but
  produces much larger keys and ciphertexts for equivalent security; this matters when
  every file share stores a wrapped key per recipient.
- **No parameter choices to get wrong.** RSA needs a key size decision (and a bad one is a
  real, historically common vulnerability class); NIST P-256 has a history of implementation
  pitfalls around point validation and nonce generation in signing. X25519's design
  deliberately closes off most of the ways implementations go wrong with elliptic curves
  (complete addition formulas, no invalid-curve points to reject).
- **It pairs naturally with HKDF-SHA256** for the sharing scheme — see below.

The public key is stored in plaintext (it's public by definition — `users.public_key`).
The private key **never reaches the server in usable form** — see the next section.

## Protecting the private key: two separate Argon2id derivations

This is the detail most likely to get silently merged into one "hash the password" step
by accident, so it's worth being explicit: **there are two independent Argon2id calls in
this system, and they must never share a derivation.**

1. **Server-side login verification** (`backend/app/core/security.py`, `hash_password`/
   `verify_password`): Argon2id with `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`.
   This is what the server checks the password against. It never leaves the server and
   never derives anything else.
2. **Client-side key-wrapping derivation** (`frontend/src/crypto/keys.ts`,
   `deriveKeyWrappingKey`): a *separate* Argon2id call, run in-browser via WASM
   (`hash-wasm`), with deliberately lighter parameters (`iterations=3`,
   `memorySize=19 MiB`) than the server's — this one runs on every unlock, including on
   weaker client devices, so it's tuned down from the server-side defaults. Its only job is
   producing the AES-256-GCM key that wraps the user's private key
   (`encryptPrivateKey`/`decryptPrivateKey`).

**Why two, not one?** If the server ever derived the wrapping key itself (e.g. by reusing
the login hash, or by deriving both from one call), a server compromise would let the
attacker *compute* the wrapping key and decrypt every stored private key — defeating the
entire point of encrypting it client-side in the first place. Keeping the derivations
independent means a server-side breach exposes password *hashes* (which Argon2id already
makes expensive to crack) but never touches the material that protects private keys. The
two calls use different salts (`private_key_kdf_salt` is random and stored per-user,
unrelated to whatever salt the login hash uses internally) and run in different places
entirely (server vs. browser WASM).

The practical consequence: **the server cannot decrypt a user's private key even if it
wanted to.** It never sees the plaintext password used for key derivation for a long
enough window to compute anything from it — the password is used transiently during
login/register to run the above derivation client-side, then discarded.

## File encryption: AES-256-GCM, chunked, random key per file

Every file gets a **fresh random 256-bit AES key**, generated in the browser
(`generateFileKey`, `frontend/src/crypto/aes.ts`) and never reused across files. AES-GCM
specifically (not CBC, not plain CTR) because it's an **AEAD** cipher — it provides
authenticity and tamper-detection as a built-in property of the primitive, not as a
bolted-on HMAC a developer has to remember to add and get the construction order right on
(the historically common "encrypt-and-MAC vs. MAC-then-encrypt" class of mistakes simply
doesn't exist with GCM). The tamper-detection is exercised directly in
`crypto.test.ts` — a flipped ciphertext bit fails to decrypt rather than silently returning
corrupted plaintext — and in `download.ts`, which aborts the whole download on the first
chunk that fails authentication rather than assembling a partially-tampered file.

**Chunking** (4 MiB chunks, `upload.ts` / `max_chunk_size_bytes`) exists for two reasons:
large files can't be held fully in browser memory as both plaintext and ciphertext
simultaneously without risk of exhausting it, and it lets upload/download report real
progress instead of one opaque all-or-nothing operation.

### Nonce construction: why a counter, not fully random, per chunk

This is the detail the project's nonce-reuse attack demonstration (`docs/attack-demo.md`)
exists to make concrete, so it's worth explaining the reasoning up front. **AES-GCM's
security collapses completely if the same (key, nonce) pair ever encrypts two different
messages** — not "weakens," collapses: an attacker who observes two ciphertexts under a
reused nonce can XOR them to recover the XOR of the two plaintexts, and can forge
valid-looking ciphertext for anything they can predict (see `docs/attack-demo.md` for a
live demonstration of exactly this).

A naive design generates each chunk's nonce with `crypto.getRandomValues(new
Uint8Array(12))` independently. For a 96-bit random nonce, the birthday bound means
collision probability becomes non-negligible around 2⁴⁸ encryptions *under the same key* —
far beyond any single file's chunk count, but this project generates a *fresh key per
file*, so the realistic risk isn't within-file collision, it's that "independently random
every time" offers no structural guarantee at all, just a probabilistic one that degrades
if usage patterns ever change (e.g. a future refactor that reuses a file key across
re-uploads).

Instead, `chunkNonce()` (`frontend/src/crypto/aes.ts`) builds each chunk's nonce as a
**random 4-byte per-file prefix + an 8-byte big-endian chunk counter**. This makes
uniqueness *deterministic*, not probabilistic: as long as chunk indices don't repeat
within a file (which the upload loop guarantees by construction), the nonce cannot repeat,
full stop — no birthday bound to reason about. Verified directly in `crypto.test.ts`,
which generates 1,000 chunk nonces under one prefix and asserts zero collisions.

## Sharing: X25519 + HKDF-SHA256, ECIES-style

Sharing a file means wrapping its AES key to a recipient's X25519 public key
(`wrapFileKey`/`unwrapFileKey`, `frontend/src/crypto/wrap.ts`):

1. Generate a **fresh ephemeral X25519 keypair** for this one share.
2. Compute `X25519(ephemeral_private, recipient_public)` — a shared secret only the
   recipient (who holds the matching static private key) can also compute, via
   `X25519(recipient_private, ephemeral_public)`.
3. Run the shared secret through **HKDF-SHA256** with a fixed info string
   (`"cryptvault-file-key-wrap-v1"`) to derive an AES-256-GCM key.
4. Encrypt the file's content key under that derived key.

This is a standard ECIES construction. Two choices worth explaining:

- **A fresh ephemeral keypair per share**, not reusing one static sender key. This means
  each share's wrapped-key ciphertext is independent — compromising one share's ephemeral
  private key (which isn't stored anywhere past the wrapping operation) reveals nothing
  about any other share of the same or different files. It does **not**, however, give the
  overall system forward secrecy — see `limitations.md`'s dedicated section on exactly
  what this does and doesn't buy.
- **HKDF with a fixed info string**, rather than using the raw X25519 shared secret
  directly as an AES key. HKDF's job is domain separation and key-derivation hygiene — the
  info string ties the derived key specifically to "this is a CryptVault file-key wrap,"
  so the same shared secret could never accidentally collide with a key derived for some
  other purpose if this codebase ever reuses X25519 agreement elsewhere.

The **owner's own access is just a share to themselves** — at upload time, the uploader
wraps the file key to their *own* public key (`upload.ts`) and stores it as a
`FileKeyShare` row with `permission=owner`. This isn't a shortcut; it's what makes access
control uniform: every reader, owner or recipient, proves access the same way (holding a
wrapped key they can unwrap), and the backend's access check (`_get_file_with_access`) is
one query against one table regardless of who's asking.

## Session tokens: JWT, HS256

Access tokens (15 min) and refresh tokens (7 days) are JWTs, each with a random `jti` so no
two are ever identical. The access token travels as a bearer header and lives only in JS
memory; the refresh token travels only as an `HttpOnly`, `SameSite=Strict` cookie that page
script can't read. Both are signed with HS256 — symmetric
HMAC, not RS256/ES256 asymmetric signing. This is a deliberate, not default, choice:
asymmetric signing exists to let a party *other than the issuer* verify a token without
being able to forge one (e.g. multiple independent services checking tokens issued by one
auth server). This project has exactly one issuer and one verifier — the same backend
process — so there is no actor who needs to verify without the ability to issue, and HS256
avoids the overhead and key-management surface of a public/private signing keypair for no
real benefit here.

A third, distinct token type exists for the two-step MFA flow: `create_mfa_token`
(`core/security.py`) issues a token with `type: "mfa_pending"` and a 5-minute expiry, and
every endpoint that accepts one explicitly checks that `type` field
(`resolve_mfa_user`, `services/login.py`). This isn't just "a shorter-lived access token" —
it's a *different* token type specifically so an `mfa_pending` token (which proves only
"this subject's password checked out") can never be mistaken for or substituted into a
context expecting a full access token. Type confusion between token purposes is a real,
recurring JWT vulnerability class; checking the type explicitly rather than relying on
scope/expiry alone closes it off structurally.

## TOTP secrets: envelope encryption, a third independent key

TOTP secrets are encrypted at rest (`encrypt_secret`/`decrypt_secret`, `core/security.py`)
using AES-256-GCM under `secret_encryption_key` — a server-side key that is **independent
of both the JWT signing secret and the password-hashing process**. Three secrets, three
independent purposes, deliberately not derived from one another: a leak of the JWT secret
lets an attacker forge session tokens but not decrypt TOTP seeds; a leak of the TOTP
encryption key lets an attacker compute valid 2FA codes but not forge arbitrary sessions
or crack passwords faster. Collapsing these into one "app secret" is a common shortcut that
turns every key's blast radius into the sum of all of them.

## WebAuthn / passkeys

Implemented via `py_webauthn` (server) and `@simplewebauthn/browser` (client) — see
`api/v1/mfa.py`. The property that makes WebAuthn worth the implementation complexity over
"just TOTP": it's **structurally phishing-resistant**. A TOTP code is a shared secret the
user can be tricked into typing into a fake site, which the fake site can immediately
replay against the real one. A WebAuthn assertion is cryptographically bound to the origin
that requested it by the browser itself, before the user's authenticator ever signs
anything — a phishing site at `cryptvau1t.com` cannot obtain a valid assertion for
`cryptvault.com` no matter what the user does, because the browser never lets it ask.
Verified against a real (if emulated) authenticator via Playwright's CDP virtual
authenticator in `e2e/webauthn-smoke.mjs`, including that an unenrolled authenticator is
correctly rejected.

## Audit log integrity: SHA-256 hash chain

Each entry's hash covers the previous entry's hash plus its own fields
(`services/audit.py`): `entry_hash = SHA256(prev_hash || actor_id || action || target_type
|| target_id || timestamp)`. This isn't encryption — audit log entries aren't secret — it's
**tamper-evidence**: modifying or deleting any entry breaks the hash chain for every entry
after it, detectable by `verify_chain()` re-walking the log and recomputing. A plain
append-only table with no chaining would let someone with DB write access edit history
undetectably; the hash chain turns "undetectable" into "detectable after the fact," which
is the best a server-side-only mechanism can offer without external, tamper-proof log
shipping (out of scope for this project's size).

## What's deliberately *not* here

No custom cryptographic primitives were implemented — every primitive above (AES-GCM,
X25519, HKDF-SHA256, Argon2id, SHA-256, HMAC) is a standard, widely-reviewed construction
used through audited libraries (`@noble/curves`/`@noble/hashes` client-side,
`cryptography`/`argon2-cffi` server-side), never hand-rolled. The one place this project
*does* implement a textbook algorithm from scratch is the RFC 6238 TOTP generator in
`e2e/totp-smoke.mjs` — and that's a test-only tool for generating valid codes to feed back
into the real implementation, not something shipped in the app.
