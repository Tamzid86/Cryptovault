import { createContext, useContext } from 'react';

export interface Identity {
  email: string;
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

export type LoginOutcome =
  | { needsMfa: false }
  | { needsMfa: true; methods: string[]; mfaToken: string };

export interface AuthState {
  identity: Identity | null;
  isAuthenticated: boolean;
  restoring: boolean;
  register: (email: string, password: string) => Promise<void>;
  login: (email: string, password: string) => Promise<LoginOutcome>;
  completeTotpMfa: (email: string, password: string, mfaToken: string, code: string) => Promise<void>;
  completeWebauthnMfa: (email: string, password: string, mfaToken: string) => Promise<void>;
  logout: () => void;
  logoutEverywhere: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
