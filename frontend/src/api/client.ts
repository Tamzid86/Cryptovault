import axios, { type InternalAxiosRequestConfig } from 'axios';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1',
  withCredentials: true,
});

export interface RefreshResult {
  access_token: string;
  email: string;
}

let accessToken: string | null = null;
let onSessionExpired: (() => void) | null = null;
let refreshInFlight: Promise<RefreshResult> | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function setSessionExpiredHandler(handler: (() => void) | null): void {
  onSessionExpired = handler;
}

export function refreshSession(): Promise<RefreshResult> {
  refreshInFlight ??= api
    .post<RefreshResult>('/auth/refresh')
    .then(({ data }) => {
      accessToken = data.access_token;
      return data;
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.set('Authorization', `Bearer ${accessToken}`);
  }
  return config;
});

api.interceptors.response.use(undefined, async (error) => {
  const original = error.config as (InternalAxiosRequestConfig & { _retried?: boolean }) | undefined;
  const isSessionCall = original?.url === '/auth/refresh' || original?.url === '/auth/logout';

  if (error.response?.status !== 401 || !original || original._retried || isSessionCall || !accessToken) {
    throw error;
  }
  original._retried = true;

  try {
    await refreshSession();
  } catch {
    accessToken = null;
    onSessionExpired?.();
    throw error;
  }

  return api(original);
});
