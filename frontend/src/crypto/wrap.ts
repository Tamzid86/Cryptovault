import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

const HKDF_INFO = new TextEncoder().encode('cryptvault-file-key-wrap-v1');

export interface WrappedKey {
  ephemeralPublicKey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export async function wrapFileKey(recipientPublicKey: Uint8Array, fileKeyRaw: Uint8Array): Promise<WrappedKey> {
  const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);

  const wrappingKeyRaw = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32);
  const wrappingKey = await crypto.subtle.importKey('raw', new Uint8Array(wrappingKeyRaw), 'AES-GCM', false, [
    'encrypt',
  ]);

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, wrappingKey, new Uint8Array(fileKeyRaw)),
  );

  return { ephemeralPublicKey, nonce, ciphertext };
}

export async function unwrapFileKey(
  recipientPrivateKey: CryptoKey,
  wrapped: WrappedKey,
): Promise<Uint8Array> {
  const ephemeralPublicKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(wrapped.ephemeralPublicKey),
    { name: 'X25519' },
    true,
    [],
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'X25519', public: ephemeralPublicKey }, recipientPrivateKey, 256),
  );
  const wrappingKeyRaw = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32);
  const wrappingKey = await crypto.subtle.importKey('raw', new Uint8Array(wrappingKeyRaw), 'AES-GCM', false, [
    'decrypt',
  ]);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(wrapped.nonce) },
    wrappingKey,
    new Uint8Array(wrapped.ciphertext),
  );
  return new Uint8Array(plaintext);
}
