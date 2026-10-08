import type { Identity } from '../auth/authState';
import type { FileSummary } from '../api/files';
import { downloadChunk } from '../api/files';
import { decryptChunk } from '../crypto/aes';
import { decryptFilename, unwrapFileKeyForSummary } from './fileKey';

export async function downloadFile(summary: FileSummary, identity: Identity): Promise<{ name: string; blob: Blob }> {
  const fileKey = await unwrapFileKeyForSummary(summary, identity);
  const name = await decryptFilename(summary, fileKey);

  const parts: Uint8Array[] = [];
  for (let i = 0; i < summary.num_chunks; i++) {
    const { nonce, ciphertext } = await downloadChunk(summary.id, i);
    const plaintext = await decryptChunk(fileKey, nonce, ciphertext);
    parts.push(plaintext);
  }

  return { name, blob: new Blob(parts.map((p) => new Uint8Array(p))) };
}

export function saveBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
