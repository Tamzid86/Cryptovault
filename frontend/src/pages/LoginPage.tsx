import axios from 'axios';
import { useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/authState';

function errorDetail(err: unknown, fallback: string): string {
  const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null;
  return typeof detail === 'string' ? detail : fallback;
}

export function LoginPage() {
  const { login, completeTotpMfa, completeWebauthnMfa, isAuthenticated, restoring } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [mfa, setMfa] = useState<{ methods: string[]; mfaToken: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const outcome = await login(email, password);
      if (outcome.needsMfa) {
        setMfa({ methods: outcome.methods, mfaToken: outcome.mfaToken });
      } else {
        navigate('/dashboard');
      }
    } catch (err) {
      setError(errorDetail(err, 'Login failed'));
    } finally {
      setBusy(false);
    }
  }

  async function handleTotpSubmit(e: FormEvent) {
    e.preventDefault();
    if (!mfa) return;
    setError(null);
    setBusy(true);
    try {
      await completeTotpMfa(email, password, mfa.mfaToken, totpCode);
      navigate('/dashboard');
    } catch (err) {
      setError(errorDetail(err, 'Invalid code'));
    } finally {
      setBusy(false);
    }
  }

  async function handleWebauthnClick() {
    if (!mfa) return;
    setError(null);
    setBusy(true);
    try {
      await completeWebauthnMfa(email, password, mfa.mfaToken);
      navigate('/dashboard');
    } catch (err) {
      setError(errorDetail(err, 'Passkey verification failed'));
    } finally {
      setBusy(false);
    }
  }

  if (mfa) {
    return (
      <div className="auth-page">
        <div className="auth-form">
          <h1>Verify it's you</h1>
          <p className="auth-subtitle">This account has an extra sign-in step enabled.</p>

          {mfa.methods.includes('webauthn') && (
            <button onClick={handleWebauthnClick} disabled={busy}>
              {busy ? 'Waiting for passkey…' : 'Use a passkey'}
            </button>
          )}

          {mfa.methods.includes('totp') && (
            <form onSubmit={handleTotpSubmit}>
              <label htmlFor="totp">Authenticator code</label>
              <input
                id="totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                maxLength={6}
                required
              />
              <button type="submit" disabled={busy}>
                {busy ? 'Verifying…' : 'Verify'}
              </button>
            </form>
          )}

          {error && <p className="auth-error">{error}</p>}
        </div>
      </div>
    );
  }

  if (restoring) return null;
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  return (
    <div className="auth-page">
      <form className="auth-form" onSubmit={handlePasswordSubmit}>
        <h1>Log in</h1>

        <label htmlFor="email">Email</label>
        <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        {error && <p className="auth-error">{error}</p>}

        <button type="submit" disabled={busy}>
          {busy ? 'Logging in…' : 'Log in'}
        </button>

        <p className="auth-switch">
          No account yet? <Link to="/register">Create one</Link>
        </p>
      </form>
    </div>
  );
}
