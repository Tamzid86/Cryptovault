import { api } from './client';

export interface TotpSetupResponse {
  secret: string;
  otpauth_uri: string;
  qr_code_data_uri: string;
}

export async function totpSetup(): Promise<TotpSetupResponse> {
  const { data } = await api.post<TotpSetupResponse>('/auth/totp/setup');
  return data;
}

export async function totpVerify(code: string): Promise<void> {
  await api.post('/auth/totp/verify', { code });
}

export async function totpDisable(password: string): Promise<void> {
  await api.post('/auth/totp/disable', { password });
}

export async function webauthnRegisterOptions(): Promise<object> {
  const { data } = await api.post('/auth/webauthn/register/options');
  return data;
}

export async function webauthnRegisterVerify(credential: object): Promise<void> {
  await api.post('/auth/webauthn/register/verify', { credential });
}

export async function webauthnLoginOptions(mfaToken: string): Promise<object> {
  const { data } = await api.post('/auth/webauthn/login/options', { mfa_token: mfaToken });
  return data;
}
