const NONCE_LENGTH = 12;

export async function generateFileKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function importKey(raw: Uint8Array, extractable = true): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new Uint8Array(raw), 'AES-GCM', extractable, ['encrypt', 'decrypt']);
}

export function makeNoncePrefix(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(4));
}

export function chunkNonce(prefix: Uint8Array, chunkIndex: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_LENGTH);
  nonce.set(prefix, 0);
  const view = new DataView(nonce.buffer);
  view.setUint32(4, Math.floor(chunkIndex / 2 ** 32), false);
  view.setUint32(8, chunkIndex >>> 0, false);
  return nonce;
}

export async function encryptChunk(key: CryptoKey, nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = new Uint8Array(nonce);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array(plaintext)));
}

export async function decryptChunk(key: CryptoKey, nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const iv = new Uint8Array(nonce);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, new Uint8Array(ciphertext)));
}
