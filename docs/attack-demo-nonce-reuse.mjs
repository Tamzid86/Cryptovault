import { webcrypto as crypto } from 'node:crypto';

async function aesGcmEncrypt(key, nonce, plaintext) {
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);
  return new Uint8Array(ciphertext);
}

async function aesGcmDecrypt(key, nonce, ciphertext) {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext);
  return new Uint8Array(plaintext);
}

function xor(a, b) {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

function toText(bytes) {
  return new TextDecoder().decode(bytes);
}

async function main() {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

  console.log('=== PART 1: what nonce reuse actually breaks ===\n');

  const reusedNonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintextA = new TextEncoder().encode('Account number: 4111-2222-3333-4444');
  const plaintextB = new TextEncoder().encode('Account number: 5500-6600-7700-8800');

  const ciphertextA = await aesGcmEncrypt(key, reusedNonce, plaintextA);
  const ciphertextB = await aesGcmEncrypt(key, reusedNonce, plaintextB);

  console.log('Plaintext A:', toText(plaintextA));
  console.log('Plaintext B:', toText(plaintextB));
  console.log('Same nonce used for both:', Buffer.from(reusedNonce).toString('hex'));

  const bodyA = ciphertextA.slice(0, ciphertextA.length - 16);
  const bodyB = ciphertextB.slice(0, ciphertextB.length - 16);
  const recoveredXor = xor(bodyA, bodyB);
  const trueXor = xor(plaintextA, plaintextB);

  const matches = Buffer.from(recoveredXor).equals(Buffer.from(trueXor));
  console.log('\nAttacker computes C_A xor C_B from ciphertext alone (no key needed).');
  console.log('Does it equal the true P_A xor P_B?', matches);

  if (!matches) throw new Error('Demonstration invariant broken -- investigate before trusting this script');

  const crib = new TextEncoder().encode('Account number: ');
  const guessWindow = recoveredXor.slice(0, crib.length);
  const recoveredFragmentOfB = xor(guessWindow, crib);
  console.log(`\nAttacker guesses plaintext A starts with "${toText(crib)}" (a very guessable crib).`);
  console.log('XOR-ing that guess into the recovered P_A xor P_B reveals the same region of B:');
  console.log(`  Recovered fragment of B: "${toText(recoveredFragmentOfB)}"`);
  console.log(`  Actual start of B:       "${toText(plaintextB.slice(0, crib.length))}"`);
  console.log('Confidentiality of BOTH messages is broken using only the ciphertext and one guess.');

  console.log('\n=== PART 2: why chunkNonce() makes this structurally impossible ===\n');

  function chunkNonce(prefix, chunkIndex) {
    const nonce = new Uint8Array(12);
    nonce.set(prefix, 0);
    const view = new DataView(nonce.buffer);
    view.setUint32(4, Math.floor(chunkIndex / 2 ** 32), false);
    view.setUint32(8, chunkIndex >>> 0, false);
    return nonce;
  }

  const prefix = crypto.getRandomValues(new Uint8Array(4));
  const nonces = new Set();
  const COUNT = 100_000;
  for (let i = 0; i < COUNT; i++) {
    nonces.add(Buffer.from(chunkNonce(prefix, i)).toString('hex'));
  }
  console.log(`Generated ${COUNT.toLocaleString()} chunk nonces under one random prefix.`);
  console.log(`Unique nonces: ${nonces.size.toLocaleString()} (collision iff < ${COUNT.toLocaleString()})`);
  console.log(
    nonces.size === COUNT
      ? 'Zero collisions -- guaranteed by construction (counter never repeats), not by luck.'
      : '*** COLLISION DETECTED -- this would be a critical bug ***',
  );

  if (nonces.size !== COUNT) process.exitCode = 1;
}

main().catch((err) => {
  console.error('Script error:', err);
  process.exitCode = 10;
});
