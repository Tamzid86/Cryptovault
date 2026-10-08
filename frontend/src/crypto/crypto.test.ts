import { describe, expect, it } from 'vitest';
import { chunkNonce, decryptChunk, encryptChunk, exportKey, generateFileKey, importKey, makeNoncePrefix } from './aes';
import {
  decryptPrivateKey,
  deriveKeyWrappingKey,
  encryptPrivateKey,
  generateKeyPair,
  importPrivateKey,
  randomSalt,
} from './keys';
import { fingerprint } from './fingerprint';
import { unwrapFileKey, wrapFileKey } from './wrap';

describe('X25519 identity keys', () => {
  it('generates a 32-byte keypair', () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(publicKey.length).toBe(32);
    expect(privateKey.length).toBe(32);
  });

  it('password-derived key round-trips the private key through AES-GCM', async () => {
    const { privateKey } = generateKeyPair();
    const salt = randomSalt();
    const wrappingKey = await deriveKeyWrappingKey('correct-horse-battery-staple', salt);

    const { ciphertext, nonce } = await encryptPrivateKey(wrappingKey, privateKey);
    expect(ciphertext).not.toEqual(privateKey);

    const sameWrappingKey = await deriveKeyWrappingKey('correct-horse-battery-staple', salt);
    const recovered = await decryptPrivateKey(sameWrappingKey, ciphertext, nonce);
    expect(recovered).toEqual(privateKey);
  });

  it('imports the private key as non-extractable, so its bytes can never be read back', async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const key = await importPrivateKey(privateKey, publicKey);

    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', key)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', key)).rejects.toThrow();
  });

  it('rejects the wrong password when unwrapping the private key', async () => {
    const { privateKey } = generateKeyPair();
    const salt = randomSalt();
    const wrappingKey = await deriveKeyWrappingKey('correct-horse-battery-staple', salt);
    const { ciphertext, nonce } = await encryptPrivateKey(wrappingKey, privateKey);

    const wrongKey = await deriveKeyWrappingKey('totally-wrong-password', salt);
    await expect(decryptPrivateKey(wrongKey, ciphertext, nonce)).rejects.toThrow();
  });
});

describe('AES-256-GCM chunked file encryption', () => {
  it('round-trips a chunk of plaintext', async () => {
    const key = await generateFileKey();
    const prefix = makeNoncePrefix();
    const nonce = chunkNonce(prefix, 0);
    const plaintext = new TextEncoder().encode('hello cryptvault');

    const ciphertext = await encryptChunk(key, nonce, plaintext);
    const recovered = await decryptChunk(key, nonce, ciphertext);

    expect(recovered).toEqual(plaintext);
  });

  it('produces distinct nonces per chunk index under the same prefix', () => {
    const prefix = makeNoncePrefix();
    const nonces = Array.from({ length: 1000 }, (_, i) => chunkNonce(prefix, i));
    const unique = new Set(nonces.map((n) => Array.from(n).join(',')));
    expect(unique.size).toBe(1000);
  });

  it('fails to decrypt a chunk under the wrong nonce (tamper/reorder detection)', async () => {
    const key = await generateFileKey();
    const prefix = makeNoncePrefix();
    const plaintext = new TextEncoder().encode('chunk zero');
    const ciphertext = await encryptChunk(key, chunkNonce(prefix, 0), plaintext);

    await expect(decryptChunk(key, chunkNonce(prefix, 1), ciphertext)).rejects.toThrow();
  });

  it('round-trips an exported/imported raw key', async () => {
    const key = await generateFileKey();
    const raw = await exportKey(key);
    expect(raw.length).toBe(32); // AES-256

    const reimported = await importKey(raw);
    const nonce = chunkNonce(makeNoncePrefix(), 0);
    const plaintext = new TextEncoder().encode('round trip');
    const ciphertext = await encryptChunk(key, nonce, plaintext);
    const recovered = await decryptChunk(reimported, nonce, ciphertext);
    expect(recovered).toEqual(plaintext);
  });
});

describe('X25519 + HKDF key wrapping for sharing', () => {
  it('lets the recipient unwrap a file key wrapped to their public key', async () => {
    const recipient = generateKeyPair();
    const fileKey = await generateFileKey();
    const fileKeyRaw = await exportKey(fileKey);

    const wrapped = await wrapFileKey(recipient.publicKey, fileKeyRaw);
    const recipientKey = await importPrivateKey(recipient.privateKey, recipient.publicKey);
    const unwrapped = await unwrapFileKey(recipientKey, wrapped);

    expect(unwrapped).toEqual(fileKeyRaw);
  });

  it('fails to unwrap with a different recipient private key', async () => {
    const recipient = generateKeyPair();
    const attacker = generateKeyPair();
    const fileKey = await generateFileKey();
    const fileKeyRaw = await exportKey(fileKey);

    const wrapped = await wrapFileKey(recipient.publicKey, fileKeyRaw);
    const attackerKey = await importPrivateKey(attacker.privateKey, attacker.publicKey);
    await expect(unwrapFileKey(attackerKey, wrapped)).rejects.toThrow();
  });

  it('produces a different ephemeral key and ciphertext on every wrap (no key/nonce reuse)', async () => {
    const recipient = generateKeyPair();
    const fileKey = await generateFileKey();
    const fileKeyRaw = await exportKey(fileKey);

    const a = await wrapFileKey(recipient.publicKey, fileKeyRaw);
    const b = await wrapFileKey(recipient.publicKey, fileKeyRaw);

    expect(a.ephemeralPublicKey).not.toEqual(b.ephemeralPublicKey);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });
});

describe('public key fingerprints', () => {
  it('is 8 groups of 4 uppercase hex digits, stable for the same key', async () => {
    const { publicKey } = generateKeyPair();
    const fp = await fingerprint(publicKey);
    expect(fp).toMatch(/^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
    expect(await fingerprint(publicKey)).toBe(fp);
  });

  it('differs for different keys', async () => {
    expect(await fingerprint(generateKeyPair().publicKey)).not.toBe(await fingerprint(generateKeyPair().publicKey));
  });
});
