import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import { refreshSession, setAccessToken, setSessionExpiredHandler } from '../api/client';
import {
  loginMfaTotp,
  loginUser,
  logoutAllSessions,
  logoutSession,
  registerUser,
  webauthnLoginVerify,
  type LoginResult,
} from '../api/auth';
import { webauthnLoginOptions } from '../api/mfa';
import { fromBase64, toBase64 } from '../crypto/base64';
import {
  decryptPrivateKey,
  deriveKeyWrappingKey,
  encryptPrivateKey,
  generateKeyPair,
  importPrivateKey,
  randomSalt,
} from '../crypto/keys';
import { AuthContext, type AuthState, type Identity, type LoginOutcome } from './authState';
import { clearIdentity, loadIdentity, saveIdentity } from './keyStore';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [restoring, setRestoring] = useState(true);

  async function finishLogin(email: string, password: string, result: LoginResult) {
    if (!result.tokens || !result.key_bundle) {
      throw new Error('Login did not return tokens');
    }
    const salt = fromBase64(result.key_bundle.private_key_kdf_salt);
    const wrappingKey = await deriveKeyWrappingKey(password, salt);
    const rawPrivateKey = await decryptPrivateKey(
      wrappingKey,
      fromBase64(result.key_bundle.encrypted_private_key),
      fromBase64(result.key_bundle.private_key_nonce),
    );
    const publicKey = fromBase64(result.key_bundle.public_key);
    const privateKey = await importPrivateKey(rawPrivateKey, publicKey);
    rawPrivateKey.fill(0); // the raw bytes aren't needed past this point

    const next = { email, publicKey, privateKey };
    setAccessToken(result.tokens.access_token);
    setIdentity(next);
    await saveIdentity(next).catch(() => {
    });
  }

  async function login(email: string, password: string): Promise<LoginOutcome> {
    const result = await loginUser(email, password);
    if (result.mfa_required) {
      return { needsMfa: true, methods: result.methods ?? [], mfaToken: result.mfa_token! };
    }
    await finishLogin(email, password, result);
    return { needsMfa: false };
  }

  async function completeTotpMfa(email: string, password: string, mfaToken: string, code: string) {
    const result = await loginMfaTotp(mfaToken, code);
    await finishLogin(email, password, result);
  }

  async function completeWebauthnMfa(email: string, password: string, mfaToken: string) {
    const optionsJSON = await webauthnLoginOptions(mfaToken);
    const credential = await startAuthentication({ optionsJSON: optionsJSON as never });
    const result = await webauthnLoginVerify(mfaToken, credential);
    await finishLogin(email, password, result);
  }

  async function register(email: string, password: string) {
    const { publicKey, privateKey } = generateKeyPair();
    const salt = randomSalt();
    const wrappingKey = await deriveKeyWrappingKey(password, salt);
    const { ciphertext, nonce } = await encryptPrivateKey(wrappingKey, privateKey);

    await registerUser({
      email,
      password,
      public_key: toBase64(publicKey),
      encrypted_private_key: toBase64(ciphertext),
      private_key_kdf_salt: toBase64(salt),
      private_key_nonce: toBase64(nonce),
    });

    await login(email, password);
  }

  function endSession() {
    setAccessToken(null);
    setIdentity(null);
    void clearIdentity().catch(() => {});
  }

  function logout() {
    void logoutSession().catch(() => {});
    endSession();
  }

  async function logoutEverywhere() {
    await logoutAllSessions();
    endSession();
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const stored = await loadIdentity().catch(() => null);
        if (!stored) return;
        try {
          const session = await refreshSession();
          if (session.email !== stored.email) throw new Error('Stored identity belongs to another account');
          if (!cancelled) setIdentity(stored);
        } catch {
          if (!cancelled) endSession();
        }
      } finally {
        if (!cancelled) setRestoring(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    setSessionExpiredHandler(endSession);
    return () => setSessionExpiredHandler(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      identity,
      isAuthenticated: identity !== null,
      restoring,
      register,
      login,
      completeTotpMfa,
      completeWebauthnMfa,
      logout,
      logoutEverywhere,
    }),
    [identity, restoring],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
