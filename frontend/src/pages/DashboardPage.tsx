import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getStorageUsage, type StorageUsage } from '../api/users';
import { fingerprint } from '../crypto/fingerprint';
import { useAuth } from '../auth/authState';
import { FileUpload } from './FileUpload';
import { FileList } from './FileList';

export function DashboardPage() {
  const { identity, logout } = useAuth();
  const [refreshKey, setRefreshKey] = useState(0);
  const [myFingerprint, setMyFingerprint] = useState<string | null>(null);
  const [storage, setStorage] = useState<StorageUsage | null>(null);

  useEffect(() => {
    if (identity) void fingerprint(identity.publicKey).then(setMyFingerprint);
  }, [identity]);

  useEffect(() => {
    void getStorageUsage().then(setStorage).catch(() => setStorage(null));
  }, [refreshKey]);

  if (!identity) return null;

  return (
    <div className="dashboard-page">
      <header className="dashboard-header">
        <h1>CryptVault</h1>
        <div>
          <Link to="/security">Security</Link>
          <button onClick={logout}>Log out</button>
        </div>
      </header>

      <section className="identity-card">
        <p>
          Signed in as <strong>{identity.email}</strong>
        </p>
        <p>
          Your key fingerprint: <code className="my-fingerprint">{myFingerprint ?? '…'}</code>
        </p>
        <p className="field-hint">
          When someone shares a file with you, they'll see this fingerprint. If you read it to each other
          and it matches, the server can't have swapped in its own key. Your private key was unlocked in
          this browser and has never been sent to the server.
        </p>
      </section>

      {storage && (
        <p className="field-hint storage-usage">
          Storage: {formatBytes(storage.used_bytes)} of {formatBytes(storage.quota_bytes)} used
        </p>
      )}

      <FileUpload onUploaded={() => setRefreshKey((k) => k + 1)} />
      <FileList refreshKey={refreshKey} onChanged={() => setRefreshKey((k) => k + 1)} />
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}
