import { api } from './client';

export interface RegisterPayload {
  email: string;
  password: string;
  public_key: string;
  encrypted_private_key: string;
  private_key_kdf_salt: string;
  private_key_nonce: string;
}

export interface RegisterResponse {
  id: string;
  email: string;
}

export interface KeyBundle {
  public_key: string;
  encrypted_private_key: string;
  private_key_kdf_salt: string;
  private_key_nonce: string;
}

export interface TokenPair {
  access_token: string;
  token_type: string;
}

export async function logoutSession(): Promise<void> {
  await api.post('/auth/logout');
}

export async function logoutAllSessions(): Promise<void> {
  await api.post('/auth/logout-all');
}

export interface LoginResult {
  mfa_required: boolean;
  methods: string[] | null;
  mfa_token: string | null;
  tokens: TokenPair | null;
  key_bundle: KeyBundle | null;
}

export async function registerUser(payload: RegisterPayload): Promise<RegisterResponse> {
  const { data } = await api.post<RegisterResponse>('/auth/register', payload);
  return data;
}

export async function loginUser(email: string, password: string): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/auth/login', { email, password });
  return data;
}

export async function loginMfaTotp(mfaToken: string, code: string): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/auth/login/mfa/totp', { mfa_token: mfaToken, code });
  return data;
}

export async function webauthnLoginVerify(mfaToken: string, credential: object): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/auth/webauthn/login/verify', { mfa_token: mfaToken, credential });
  return data;
}
