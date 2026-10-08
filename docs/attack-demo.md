# Attack & Fix Demonstration

Two demonstrations, both run for real against this project's actual code — not
hypothetical write-ups. Full terminal output is reproduced below exactly as captured.

1. **IDOR**: deliberately reintroduce the exact access-control bug the project's test
   suite is designed to catch, exploit it against a live running instance, then revert
   and show the exploit fail.
2. **AES-GCM nonce reuse**: a cryptographic (not access-control) demonstration of why
   `chunkNonce()`'s counter-based design exists, using the project's actual AES-GCM
   parameters.

## 1. IDOR — reading another user's file by ID

### The vulnerability

`backend/app/api/v1/files.py`'s `_get_file_with_access` is the one function every file
read goes through. The real, fixed version requires a matching `FileKeyShare` row for the
requesting user:

```python
# REAL (fixed) CODE:
async def _get_file_with_access(db, file_id, user_id) -> FileObject:
    result = await db.execute(
        select(FileObject)
        .join(FileKeyShare, FileKeyShare.file_id == FileObject.id)
        .where(FileObject.id == file_id, FileKeyShare.recipient_id == user_id)
    )
    file = result.scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File not found")
    return file
```

For this demonstration, it was temporarily changed to the kind of mistake a refactor
realistically introduces — simplifying the query and dropping the access filter entirely,
while leaving everything else (the 404-not-403 behavior, the function signature, every
caller) untouched:

```python
# DELIBERATELY VULNERABLE, for this demo only:
async def _get_file_with_access(db, file_id, user_id) -> FileObject:
    result = await db.execute(select(FileObject).where(FileObject.id == file_id))
    file = result.scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File not found")
    return file
```

Nothing else changed. The function still returns a `FileObject` or 404; it just no longer
checks *whose* file it is.

### The exploit

[`docs/attack-demo-idor.mjs`](attack-demo-idor.mjs) registers two unrelated users, has one
upload a file, and has the other request its content using nothing but their own valid
session token:

```
$ node docs/attack-demo-idor.mjs

Alice uploaded file 8082645c-8e7a-445a-9954-6e0117cbf6ac, never shared it with anyone.
Bob registered separately and has no relationship to Alice's file.

Bob requests GET /files/8082645c-8e7a-445a-9954-6e0117cbf6ac/chunks/0 using his own valid token...
Response status: 200
Response body: "ALICE-PRIVATE-FILE-CONTENT-1790893018114"

*** VULNERABLE: Bob received Alice's file content (leaked=true) ***
```

Bob's request carries *his own* legitimate, correctly-issued bearer token the entire time —
this isn't a token-forgery or session-hijacking bug, it's a pure authorization failure: the
server correctly identifies who's asking, and simply doesn't check whether they *should* be
allowed to see this particular file.

**Why this matters even though the content here is a plaintext marker, not real ciphertext:**
in the real app, what Bob would actually receive is AES-256-GCM ciphertext he can't decrypt
without Alice's file key — so this specific bug doesn't hand over *plaintext*. That is not
a reason to treat it as low severity. Access control and encryption are two independent
properties: encryption protects content *if* access control already failed, but it's not a
substitute for access control itself. Even ciphertext disclosure leaks real information (file
existence, size, chunk boundaries, exact upload timing via the response) to someone who was
never supposed to receive any response at all — and this exact bug, with no other change,
also breaks the share-management endpoints that reuse the same helper (see below), which
has nothing to do with encryption at all.

### The regression suite catches it from three directions

Before reverting the fix, the existing test suite was run against the vulnerable code
as-is:

```
$ pytest tests/test_files.py::test_other_user_cannot_access_file_by_guessing_id tests/test_sharing.py -v

FAILED tests/test_files.py::test_other_user_cannot_access_file_by_guessing_id
FAILED tests/test_sharing.py::test_owner_can_revoke_and_recipient_loses_access
FAILED tests/test_sharing.py::test_user_with_no_access_gets_404_on_share_management
3 failed, 9 passed in 6.06s
```

The third failure is the more interesting one: `_get_file_with_access` is also the first
check inside `_require_owner_share`, used by the share-management endpoints
(`POST/GET/DELETE /files/{id}/shares`). With the access filter gone, a user with zero
relationship to a file could reach past the first check, only to crash the server with an
unhandled `NoResultFound` at the *second* check instead of getting a clean 403/404 — this
one bug didn't just leak file content, it broke three independent code paths that all
happened to share a root dependency. That blast radius is exactly why this function has
the IDOR-prevention comment it does in the real code, and exactly the kind of thing a
focused unit test on "can a stranger read this file" doesn't by itself reveal — it took the
full sharing test suite to surface all three.

### The fix, verified

Reverting to the real code and re-running everything:

```
$ pytest -q
........................................
40 passed in 12.54s

$ node docs/attack-demo-idor.mjs

Alice uploaded file b4bda7c3-e1f8-4465-9689-5f575fc9ed07, never shared it with anyone.
Bob registered separately and has no relationship to Alice's file.

Bob requests GET /files/b4bda7c3-e1f8-4465-9689-5f575fc9ed07/chunks/0 using his own valid token...
Response status: 404

*** FIXED: Bob was correctly denied (404) ***
```

Same script, same two accounts, opposite result — purely from the one-line difference in
the WHERE clause.

## 2. AES-256-GCM nonce reuse

This one isn't an access-control bug — it's a demonstration of *why* a specific
cryptographic design choice (`chunkNonce()` in `frontend/src/crypto/aes.ts`, discussed in
`docs/crypto-design.md`) exists at all, by showing what happens without it.
[`docs/attack-demo-nonce-reuse.mjs`](attack-demo-nonce-reuse.mjs) uses Node's native
Web Crypto AES-GCM — the identical primitive the browser uses — to encrypt two different
messages under the same key *and the same nonce*, the exact mistake a naive
"just call `crypto.getRandomValues()` every time and hope" nonce scheme risks:

```
$ node docs/attack-demo-nonce-reuse.mjs

=== PART 1: what nonce reuse actually breaks ===

Plaintext A: Account number: 4111-2222-3333-4444
Plaintext B: Account number: 5500-6600-7700-8800
Same nonce used for both: 361bb1e27f3048286bcb757f

Attacker computes C_A xor C_B from ciphertext alone (no key needed).
Does it equal the true P_A xor P_B? true

Attacker guesses plaintext A starts with "Account number: " (a very guessable crib).
XOR-ing that guess into the recovered P_A xor P_B reveals the same region of B:
  Recovered fragment of B: "Account number: "
  Actual start of B:       "Account number: "
Confidentiality of BOTH messages is broken using only the ciphertext and one guess.
```

No key, no vulnerability in AES itself, no implementation bug beyond the one nonce being
reused — reusing a nonce is enough on its own to let an attacker who only ever observes
ciphertext recover the XOR of the two plaintexts, and from there, recover full plaintext
given any crib (a guessable fragment — file headers, repeated phrases, known structure all
qualify). AES-GCM's authentication guarantee is *also* broken by nonce reuse (an attacker
who recovers the keystream this way can forge valid-looking ciphertext for it), though
that half isn't demonstrated here since it needs deriving the GHASH authentication subkey,
a longer derivation than this script's point requires.

The second half shows why this project's actual nonce scheme doesn't have this exposure to
begin with — not because collisions are *unlikely*, but because they're *impossible by
construction*:

```
=== PART 2: why chunkNonce() makes this structurally impossible ===

Generated 100,000 chunk nonces under one random prefix.
Unique nonces: 100,000 (collision iff < 100,000)
Zero collisions -- guaranteed by construction (counter never repeats), not by luck.
```

`chunkNonce(prefix, chunkIndex)` builds each nonce from a random 4-byte per-file prefix plus
an 8-byte big-endian counter. As long as chunk indices within one file don't repeat — true
by construction, since the upload loop assigns them sequentially — the nonce cannot repeat.
There's no birthday bound to reason about here, because this isn't relying on randomness
for uniqueness at all.
