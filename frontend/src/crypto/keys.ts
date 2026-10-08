import { x25519 } from '@noble/curves/ed25519';
import { argon2id } from 'hash-wasm';
import { toBase64 } from './base64';

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

const toBase64Url = (bytes: Uint8Array) => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export async function importPrivateKey(privateKey: Uint8Array, publicKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'X25519', d: toBase64Url(privateKey), x: toBase64Url(publicKey) },
    { name: 'X25519' },
    false,
    ['deriveBits'],
  );
}

export function randomSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

const KDF_PARAMS = {
  parallelism: 1,
  iterations: 3,
  memorySize: 19456, // 19 MiB
  hashLength: 32,
  outputType: 'binary' as const,
};

export async function deriveKeyWrappingKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const derived = await argon2id({ password, salt, ...KDF_PARAMS });
  return crypto.subtle.importKey('raw', new Uint8Array(derived as Uint8Array), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function encryptPrivateKey(
  wrappingKey: CryptoKey,
  privateKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, wrappingKey, new Uint8Array(privateKey)),
  );
  return { ciphertext, nonce };
}

export async function decryptPrivateKey(
  wrappingKey: CryptoKey,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(nonce) },
    wrappingKey,
    new Uint8Array(ciphertext),
  );
  return new Uint8Array(plaintext);
}
