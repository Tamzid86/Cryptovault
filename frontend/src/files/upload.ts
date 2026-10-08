import type { Identity } from '../auth/authState';
import { createFile, uploadChunk } from '../api/files';
import { toBase64 } from '../crypto/base64';
import { chunkNonce, encryptChunk, exportKey, generateFileKey, makeNoncePrefix } from '../crypto/aes';
import { wrapFileKey } from '../crypto/wrap';

const CHUNK_SIZE = 4 * 1024 * 1024;

export async function uploadFile(file: File, identity: Identity, onProgress?: (fraction: number) => void): Promise<string> {
  const fileKey = await generateFileKey();
  const fileKeyRaw = await exportKey(fileKey);

  const filenameNonce = crypto.getRandomValues(new Uint8Array(12));
  const encryptedFilename = await encryptChunk(fileKey, filenameNonce, new TextEncoder().encode(file.name));

  const numChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  const noncePrefix = makeNoncePrefix();

  const wrapped = await wrapFileKey(identity.publicKey, fileKeyRaw);

  const { id: fileId } = await createFile({
    encrypted_filename: toBase64(encryptedFilename),
    filename_nonce: toBase64(filenameNonce),
    size_bytes: file.size,
    chunk_size: CHUNK_SIZE,
    num_chunks: numChunks,
    ephemeral_public_key: toBase64(wrapped.ephemeralPublicKey),
    wrapped_key: toBase64(wrapped.ciphertext),
    wrap_nonce: toBase64(wrapped.nonce),
  });

  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
    const nonce = chunkNonce(noncePrefix, i);
    const ciphertext = await encryptChunk(fileKey, nonce, plaintext);

    await uploadChunk(fileId, i, nonce, ciphertext);
    onProgress?.((i + 1) / numChunks);
  }

  return fileId;
}
