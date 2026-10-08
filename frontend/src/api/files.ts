import { api } from './client';
import { fromBase64, toBase64 } from '../crypto/base64';

export interface FileKeyShareOut {
  ephemeral_public_key: string;
  wrapped_key: string;
  wrap_nonce: string;
  permission: string;
}

export interface FileSummary {
  id: string;
  owner_id: string;
  encrypted_filename: string;
  filename_nonce: string;
  size_bytes: number;
  chunk_size: number;
  num_chunks: number;
  created_at: string;
  key_share: FileKeyShareOut;
}

export interface CreateFilePayload {
  encrypted_filename: string;
  filename_nonce: string;
  size_bytes: number;
  chunk_size: number;
  num_chunks: number;
  ephemeral_public_key: string;
  wrapped_key: string;
  wrap_nonce: string;
}

export async function createFile(payload: CreateFilePayload): Promise<{ id: string }> {
  const { data } = await api.post<{ id: string }>('/files', payload);
  return data;
}

export async function listFiles(): Promise<FileSummary[]> {
  const { data } = await api.get<FileSummary[]>('/files');
  return data;
}

export async function uploadChunk(fileId: string, chunkIndex: number, nonce: Uint8Array, ciphertext: Uint8Array): Promise<void> {
  await api.put(`/files/${fileId}/chunks/${chunkIndex}`, ciphertext, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Chunk-Nonce': toBase64(nonce),
    },
  });
}

export async function downloadChunk(fileId: string, chunkIndex: number): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const res = await api.get(`/files/${fileId}/chunks/${chunkIndex}`, { responseType: 'arraybuffer' });
  const nonceHeader = res.headers['x-chunk-nonce'] as string;
  return { nonce: fromBase64(nonceHeader), ciphertext: new Uint8Array(res.data as ArrayBuffer) };
}

export async function deleteFile(fileId: string): Promise<void> {
  await api.delete(`/files/${fileId}`);
}

export interface CreateSharePayload {
  recipient_email: string;
  ephemeral_public_key: string;
  wrapped_key: string;
  wrap_nonce: string;
}

export interface ShareOut {
  recipient_id: string;
  recipient_email: string;
  permission: string;
  created_at: string;
}

export async function createShare(fileId: string, payload: CreateSharePayload): Promise<ShareOut> {
  const { data } = await api.post<ShareOut>(`/files/${fileId}/shares`, payload);
  return data;
}

export async function listShares(fileId: string): Promise<ShareOut[]> {
  const { data } = await api.get<ShareOut[]>(`/files/${fileId}/shares`);
  return data;
}

export async function revokeShare(fileId: string, recipientId: string): Promise<void> {
  await api.delete(`/files/${fileId}/shares/${recipientId}`);
}
