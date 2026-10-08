import type { Identity } from '../auth/authState';
import type { FileSummary } from '../api/files';
import { fromBase64 } from '../crypto/base64';
import { decryptChunk, importKey } from '../crypto/aes';
import { unwrapFileKey } from '../crypto/wrap';

export async function unwrapFileKeyForSummary(f: FileSummary, identity: Identity): Promise<CryptoKey> {
  const raw = await unwrapFileKey(identity.privateKey, {
    ephemeralPublicKey: fromBase64(f.key_share.ephemeral_public_key),
    nonce: fromBase64(f.key_share.wrap_nonce),
    ciphertext: fromBase64(f.key_share.wrapped_key),
  });
  return importKey(raw);
}

export async function decryptFilename(f: FileSummary, fileKey: CryptoKey): Promise<string> {
  const nameBytes = await decryptChunk(fileKey, fromBase64(f.filename_nonce), fromBase64(f.encrypted_filename));
  return new TextDecoder().decode(nameBytes);
}
