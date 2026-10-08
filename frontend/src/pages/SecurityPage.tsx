import axios from 'axios';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../auth/authState';
import { totpDisable, totpSetup, totpVerify, type TotpSetupResponse } from '../api/mfa';
import { getLoginEvents, getMfaStatus, type LoginEvent, type MfaStatus } from '../api/users';
import { registerPasskey } from '../mfa/webauthnRegister';

function errorDetail(err: unknown, fallback: string): string {
  const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null;
  return typeof detail === 'string' ? detail : fallback;
}

export function SecurityPage() {
  const { logoutEverywhere } = useAuth();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [events, setEvents] = useState<LoginEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [setupData, setSetupData] = useState<TotpSetupResponse | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');
  const [showDisableForm, setShowDisableForm] = useState(false);

  async function refresh() {
    const [s, e] = await Promise.all([getMfaStatus(), getLoginEvents()]);
    setStatus(s);
    setEvents(e);
  }

  useEffect(() => {
    let cancelled = false;
    Promise.all([getMfaStatus(), getLoginEvents()])
      .then(([s, e]) => {
        if (cancelled) return;
        setStatus(s);
        setEvents(e);
      })
      .catch((err) => {
        if (!cancelled) setError(errorDetail(err, 'Could not load security settings'));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleStartTotpSetup() {
    setError(null);
    setBusy(true);
    try {
      setSetupData(await totpSetup());
    } catch (err) {
      setError(errorDetail(err, 'Could not start TOTP setup'));
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyTotp() {
    setError(null);
    setBusy(true);
    try {
      await totpVerify(totpCode);
      setSetupData(null);
      setTotpCode('');
      await refresh();
    } catch (err) {
      setError(errorDetail(err, 'Invalid code'));
    } finally {
      setBusy(false);
    }
  }

  async function handleDisableTotp() {
    setError(null);
    setBusy(true);
    try {
      await totpDisable(disablePassword);
      setShowDisableForm(false);
      setDisablePassword('');
      await refresh();
    } catch (err) {
      setError(errorDetail(err, 'Could not disable TOTP'));
    } finally {
      setBusy(false);
    }
  }

  async function handleAddPasskey() {
    setError(null);
    setBusy(true);
    try {
      await registerPasskey();
      await refresh();
    } catch (err) {
      setError(errorDetail(err, 'Could not register passkey'));
    } finally {
      setBusy(false);
    }
  }

  async function handleLogoutEverywhere() {
    setError(null);
    setBusy(true);
    try {
      await logoutEverywhere();
    } catch (err) {
      setError(errorDetail(err, 'Could not sign out other sessions'));
      setBusy(false);
    }
  }

  if (!status) return error ? <p className="auth-error">{error}</p> : null;

  return (
    <div className="dashboard-page">
      <header className="dashboard-header">
        <h1>Security</h1>
        <Link to="/dashboard">Back to files</Link>
      </header>

      {error && <p className="auth-error">{error}</p>}

      <section className="identity-card">
        <h2>Authenticator app (TOTP)</h2>
        {status.totp_enabled ? (
          <>
            <p>Enabled.</p>
            {!showDisableForm ? (
              <button onClick={() => setShowDisableForm(true)}>Disable</button>
            ) : (
              <div className="share-form">
                <input
                  type="password"
                  placeholder="Confirm password"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                />
                <button onClick={handleDisableTotp} disabled={busy || !disablePassword}>
                  Confirm disable
                </button>
              </div>
            )}
          </>
        ) : setupData ? (
          <>
            <p className="field-hint">Scan this with your authenticator app, or enter the code manually:</p>
            <img src={setupData.qr_code_data_uri} alt="TOTP QR code" width={180} height={180} />
            <p>
              <code>{setupData.secret}</code>
            </p>
            <div className="share-form">
              <input
                inputMode="numeric"
                placeholder="6-digit code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                maxLength={6}
              />
              <button onClick={handleVerifyTotp} disabled={busy || totpCode.length !== 6}>
                Verify & enable
              </button>
            </div>
          </>
        ) : (
          <button onClick={handleStartTotpSetup} disabled={busy}>
            Set up authenticator app
          </button>
        )}
      </section>

      <section className="identity-card">
        <h2>Passkeys</h2>
        <p>{status.webauthn_credential_count} registered.</p>
        <button onClick={handleAddPasskey} disabled={busy}>
          Add a passkey
        </button>
      </section>

      <section className="identity-card">
        <h2>Sessions</h2>
        <p className="field-hint">
          Signs out every browser and device logged in to this account, including this one. Use it if you
          see a login you don't recognise below. Turning the authenticator app on or off, or adding a
          passkey, also signs out every other session.
        </p>
        <button onClick={handleLogoutEverywhere} disabled={busy}>
          Sign out everywhere
        </button>
      </section>

      <section className="identity-card">
        <h2>Recent activity</h2>
        <ul className="share-list">
          {events.map((e, i) => (
            <li key={i}>
              <span>
                {e.success ? 'Login' : 'Failed login'} from {e.ip_address} — {new Date(e.created_at).toLocaleString()}
                {e.is_new_device && <strong className="auth-error"> · new device</strong>}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
