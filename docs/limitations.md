# Limitations

An honest accounting of what this project does *not* solve, grouped by whether it's a
fundamental architectural trade-off (can only be mitigated differently, not "fixed" within
this design) or a scope decision (could reasonably be addressed with more time). Smaller
items already called out inline elsewhere are cross-referenced rather than repeated in
full.

## Fundamental, architectural

### Metadata leakage

The server never sees file *content*, but it necessarily sees everything around it: file
size (`size_bytes`, and ciphertext length tracks plaintext length almost exactly — AES-GCM
adds only a 16-byte tag per chunk), chunk count and therefore rough size, upload and
download timestamps, IP addresses per login (`login_events`), and the complete sharing
graph (`file_key_shares` — who a file is shared with is not encrypted, because the server
has to know who to serve wrapped keys to). Even the encrypted filename's *length* leaks
the approximate length of the real filename. None of this is incidental or an oversight —
a server that stores and serves ciphertext on demand structurally has to know how much of
it there is and who's allowed to ask for it. Traffic analysis on top of this (access
patterns, timing correlation across users) is also unaddressed. A system aiming to close
this would need fixed-size padding, oblivious access patterns (PIR-style schemes), and
timing obfuscation — all substantial complexity this project's scope didn't take on.

### Lack of forward secrecy

This is worth being precise about, because the project *does* use ephemeral keys in one
place and it would be easy to overstate what that buys. Every share wraps the file key
using a **fresh ephemeral X25519 keypair** (`wrapFileKey`, see `crypto-design.md`) — so
compromising one share's ephemeral private key (which isn't retained anywhere past the
wrap operation) reveals nothing about any other share. That's real, but it's not what
"forward secrecy" means for the system as a whole.

What actually provides forward secrecy in a system like Signal is that *both sides'* key
material rotates continuously, so a compromise of today's keys doesn't unlock yesterday's
messages. Here, the recipient's half of every ECIES wrap is their **static, long-lived
X25519 identity private key** — the same one generated once at registration and never
rotated. If that key is ever compromised (password cracked after a database leak, device
compromise, whatever), an attacker can retroactively unwrap **every file key ever shared
with that user**, past and future, for as long as the wrapped-key rows exist in the
database — because unwrapping only ever needed the recipient's static private key, nothing
from the sender's ephemeral side. The ephemeral keys protect against one failure mode
(cross-share correlation); they do nothing against the one that actually matters for
forward secrecy (identity key compromise). A design that wanted real forward secrecy would
need something like a ratchet or periodic identity key rotation with re-wrapping of active
shares — meaningfully more complexity than this project's scope.

### Trust in the server-delivered JavaScript

The one every "E2EE in a browser" product has to put in writing somewhere, because there's
no way around it with this architecture: **the server that serves `index.html` and the JS
bundle could serve a modified bundle** that exfiltrates the password before it's used for
key derivation, the decrypted private key, or decrypted file content — to anyone, at any
time, for any user who loads the page. Nothing in this design detects that, because the
verification would have to happen *before* the verifying code itself is trusted, which is
the same bootstrapping problem every pure web-based E2EE system runs into. The industry's
partial answers — Subresource Integrity hashes pinned out-of-band, a browser extension
with a fixed auditable version instead of a page fetched fresh every time, reproducible
builds with publicly verifiable build hashes, or a native app with signed auto-updates —
are not implemented here. This project's protection model is: **the server can't read
your data by looking at its own database, but it could still attack you by lying about
what code it serves.** That's a real, meaningful security property (it's the difference
between "can't read a database dump" and "can't ever be malicious"), just not an absolute
one, and conflating the two would be dishonest.

### Losing your password means losing your data — permanently

There is no password recovery flow, and *there cannot be one* without weakening the design:
the private key is encrypted under a key derived from the password
(`deriveKeyWrappingKey`, `crypto-design.md`), and the server never has access to that
derivation. A "forgot password" flow that resets the password without the private key
necessarily means either (a) the private key — and every file ever encrypted to it — is
permanently unrecoverable, or (b) the server has a way to recover the key independent of
the password, which would mean the server could decrypt it too, defeating the entire
design. This project doesn't implement any account-recovery mechanism (no backup codes, no
recovery phrase, no trusted-contact recovery) — a forgotten password is unrecoverable data
loss, full stop. Any real deployment of this design needs to make that extremely clear to
users up front, the same way hardware wallets and Signal's own key-loss stories do.

### Client-side XSS has the same blast radius as in any non-encrypted app

End-to-end encryption protects against a server operator reading the database. It does
**not** protect against a vulnerability in this project's *own* frontend code: the
decrypted private key and the plaintext of any file currently being viewed exist in the
same JavaScript execution context that a successful XSS attack would also run in. An XSS
bug in this app would be exactly as damaging as in a non-encrypted app — arguably more
relevant to call out here, precisely because the server-side encryption might create a
false impression that the client is somehow hardened too. It isn't; Semgrep and ZAP
(`security-testing.md`) didn't find an XSS vector in the current code, but that's a
statement about the current code, not a structural guarantee the architecture provides.

What *is* structural: the unlocked private key is a non-extractable WebCrypto key
(`importPrivateKey` in `frontend/src/crypto/keys.ts`), and the refresh token is an
httpOnly cookie. Injected script can use the key to decrypt files *while the page is
open*, but can't read the key's bytes or the refresh token and take them elsewhere —
so an XSS bug yields a live session to abuse, not permanent offline access to every file.

In production the page is also served with a strict Content-Security-Policy
(`frontend/nginx.conf`): no inline or `eval`'d script, scripts only from the app's own
origin, and `connect-src 'self'`. That makes the classic injected-`<script>` payload
inert, and even script that did run couldn't send decrypted data to another host. It
narrows XSS but doesn't remove the blast radius described above. A bug that runs code
*inside* the app's own bundle, or a malicious server-delivered bundle (previous section),
is untouched by CSP.

### A session survives a reload — and closing the browser

To resume after a reload, the unlocked (non-extractable) private key is kept in IndexedDB
and the refresh cookie lasts 7 days. Logging out clears both. Closing the browser *without*
logging out leaves them on disk until the next visit finds the cookie expired and wipes the
key. Someone with access to that unlocked OS account in the meantime can open the app as
the user — the same exposure as any "stay signed in" web app. On shared machines, log out.

## Scope decisions (addressable with more time, not attempted here)

- **Revoked share recipients keep offline access to content they already fetched.**
  Revocation (`DELETE /files/{id}/shares/{recipient_id}`) removes *future* access by
  deleting the wrapped-key row; it does not — cannot, without re-encrypting the file under
  a new key for every *remaining* authorized party — invalidate a key the revoked recipient
  already downloaded and could have saved locally. True revocation of already-distributed
  key material needs key rotation, not implemented here.
- **The storage quota is per account, not per person.** Each account is capped
  (`max_storage_bytes_per_user`, 1 GiB by default; see `threat-model.md`'s Denial of
  Service section), but registration is open, so someone willing to create many accounts
  gets many quotas. The register rate limit (3/minute per IP) slows that down without
  stopping it. Closing it needs sign-up gating (invites, email verification, payment),
  which this project doesn't have.
- **Revoking sessions is all-or-nothing.** "Sign out everywhere" (`/auth/logout-all`) and
  every MFA change bump the account's `token_version`, which invalidates every outstanding
  access and refresh token at once. There's no list of individual sessions to end one
  device at a time. That would need a refresh-token table instead of a single counter.
- **New-device login alerts are in-app only**, surfaced on the Security page's activity
  feed (`GET /users/me/login-events`) — there's no email or push infrastructure, so a user
  who isn't actively looking at the app won't be notified of a suspicious login in real
  time.
- **No read/download audit trail.** The hash-chained audit log records create/delete/
  share/revoke/login/MFA events, not individual chunk downloads — logging every read would
  be far noisier and wasn't judged worth the overhead for this project's scope.
- **Account enumeration via `/users/lookup`.** Any authenticated user can confirm whether
  a given email has an account — an inherent trade-off of share-by-email UX (the same one
  Google Drive and GitHub make), not an oversight. See `threat-model.md`'s Spoofing
  section.
- **WebAuthn clone detection isn't foolproof for every authenticator type.** Sign-count
  checking (`cred_row.sign_count`, `api/v1/mfa.py`) catches cloned authenticators that
  increment a counter, but some platform authenticators (notably certain passkey
  implementations syncing across devices) always report `sign_count = 0` by design, for
  which this specific detection mechanism provides no signal.
- **Container base-image CVEs awaiting upstream patches**, and the unauthenticated scope
  of the ZAP dynamic scan — both detailed in `security-testing.md` rather than repeated
  here.

## What's *not* a limitation, stated for contrast

To be clear about what the threat model and crypto design docs already establish: the
server operator cannot read file content or private keys from a database/disk compromise
alone; SQL injection, XSS, SSTI, XXE, and command injection were all actively tested
against and passed clean (`security-testing.md`); IDOR is prevented and regression-tested
from three independent code paths (`attack-demo.md`); and tampering with stored ciphertext
or the audit log is cryptographically detectable. The limitations above are the edges of a
real design, not gaps in an untested one.
