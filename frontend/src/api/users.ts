import { api } from './client';

export interface UserPublicKey {
  id: string;
  email: string;
  public_key: string;
}

export async function lookupUser(email: string): Promise<UserPublicKey> {
  const { data } = await api.get<UserPublicKey>('/users/lookup', { params: { email } });
  return data;
}

export interface MfaStatus {
  totp_enabled: boolean;
  webauthn_credential_count: number;
}

export async function getMfaStatus(): Promise<MfaStatus> {
  const { data } = await api.get<MfaStatus>('/users/me/mfa-status');
  return data;
}

export interface StorageUsage {
  used_bytes: number;
  quota_bytes: number;
}

export async function getStorageUsage(): Promise<StorageUsage> {
  const { data } = await api.get<StorageUsage>('/users/me/storage');
  return data;
}

export interface LoginEvent {
  ip_address: string;
  user_agent: string;
  success: boolean;
  is_new_device: boolean;
  created_at: string;
}

export async function getLoginEvents(): Promise<LoginEvent[]> {
  const { data } = await api.get<LoginEvent[]>('/users/me/login-events');
  return data;
}
