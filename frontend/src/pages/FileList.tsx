import axios from 'axios';
import { useEffect, useState } from 'react';
import { useAuth } from '../auth/authState';
import { deleteFile, listFiles, listShares, revokeShare, type FileSummary, type ShareOut } from '../api/files';
import { downloadFile, saveBlob } from '../files/download';
import { decryptFilename, unwrapFileKeyForSummary } from '../files/fileKey';
import { prepareShare, shareFileWithUser, type ShareCandidate } from '../files/share';

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

function errorDetail(err: unknown, fallback: string): string {
  const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null;
  return typeof detail === 'string' ? detail : fallback;
}

export function FileList({ refreshKey, onChanged }: { refreshKey: number; onChanged?: () => void }) {
  const { identity } = useAuth();
  const [files, setFiles] = useState<FileSummary[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [shares, setShares] = useState<ShareOut[]>([]);
  const [shareEmail, setShareEmail] = useState('');
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [candidate, setCandidate] = useState<ShareCandidate | null>(null);
  const [acceptChangedKey, setAcceptChangedKey] = useState(false);

  useEffect(() => {
    if (!identity) return;
    let cancelled = false;

    (async () => {
      const list = await listFiles();
      if (cancelled) return;
      setFiles(list);

      const decrypted: Record<string, string> = {};
      for (const f of list) {
        try {
          const key = await unwrapFileKeyForSummary(f, identity);
          decrypted[f.id] = await decryptFilename(f, key);
        } catch {
          decrypted[f.id] = '(could not decrypt filename)';
        }
      }
      if (!cancelled) setNames(decrypted);
    })();

    return () => {
      cancelled = true;
    };
  }, [identity, refreshKey]);

  async function handleDownload(f: FileSummary) {
    if (!identity) return;
    setBusyId(f.id);
    setError(null);
    try {
      const { name, blob } = await downloadFile(f, identity);
      saveBlob(name, blob);
    } catch {
      setError('Download failed — the file may be corrupted or tampered with.');
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(f: FileSummary) {
    setBusyId(f.id);
    setError(null);
    try {
      await deleteFile(f.id);
      setFiles((prev) => prev.filter((x) => x.id !== f.id));
      onChanged?.();
    } catch {
      setError('Delete failed');
    } finally {
      setBusyId(null);
    }
  }

  async function toggleShare(f: FileSummary) {
    if (expandedId === f.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(f.id);
    setShareEmail('');
    setShareError(null);
    setCandidate(null);
    setShares(await listShares(f.id));
  }

  async function handleLookup() {
    if (!identity || !shareEmail) return;
    setShareBusy(true);
    setShareError(null);
    setAcceptChangedKey(false);
    try {
      setCandidate(await prepareShare(shareEmail, identity));
    } catch (err) {
      setShareError(errorDetail(err, 'Could not look up that user'));
    } finally {
      setShareBusy(false);
    }
  }

  async function handleGrant(f: FileSummary) {
    if (!identity || !candidate) return;
    setShareBusy(true);
    setShareError(null);
    try {
      await shareFileWithUser(f, candidate, identity);
      setShares(await listShares(f.id));
      setShareEmail('');
      setCandidate(null);
    } catch (err) {
      setShareError(errorDetail(err, 'Could not share file'));
    } finally {
      setShareBusy(false);
    }
  }

  async function handleRevoke(f: FileSummary, recipientId: string) {
    setShareBusy(true);
    setShareError(null);
    try {
      await revokeShare(f.id, recipientId);
      setShares(await listShares(f.id));
    } catch (err) {
      setShareError(errorDetail(err, 'Could not revoke access'));
    } finally {
      setShareBusy(false);
    }
  }

  return (
    <div className="file-list">
      {error && <p className="auth-error">{error}</p>}
      {files.length === 0 && <p className="field-hint">No files yet.</p>}
      {files.map((f) => (
        <div key={f.id} className="file-item">
          <div className="file-row">
            <span className="file-name">{names[f.id] ?? 'Decrypting…'}</span>
            <span className="field-hint">{formatSize(f.size_bytes)}</span>
            <button onClick={() => handleDownload(f)} disabled={busyId === f.id}>
              Download
            </button>
            {f.key_share.permission === 'owner' && (
              <>
                <button onClick={() => toggleShare(f)}>{expandedId === f.id ? 'Close' : 'Share'}</button>
                <button onClick={() => handleDelete(f)} disabled={busyId === f.id}>
                  Delete
                </button>
              </>
            )}
          </div>

          {expandedId === f.id && (
            <div className="share-panel">
              {!candidate ? (
                <form
                  className="share-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void handleLookup();
                  }}
                >
                  <input
                    type="email"
                    placeholder="Share with email…"
                    value={shareEmail}
                    onChange={(e) => setShareEmail(e.target.value)}
                    disabled={shareBusy}
                  />
                  <button type="submit" disabled={shareBusy || !shareEmail}>
                    Look up
                  </button>
                </form>
              ) : (
                <div className={`share-confirm key-${candidate.status.kind}`} data-status={candidate.status.kind}>
                  <p>
                    Share with <strong>{candidate.email}</strong>
                  </p>
                  <p>
                    Their key fingerprint: <code className="recipient-fingerprint">{candidate.fingerprint}</code>
                  </p>
                  {candidate.status.kind === 'new' && (
                    <p className="field-hint key-status">
                      First time sharing with this person. To be sure the server gave you their real key, ask
                      them to read out the fingerprint on their dashboard and check it matches.
                    </p>
                  )}
                  {candidate.status.kind === 'match' && (
                    <p className="key-status key-ok">
                      ✓ Same key you've used for them since {new Date(candidate.status.since).toLocaleDateString()}.
                    </p>
                  )}
                  {candidate.status.kind === 'changed' && (
                    <>
                      <p className="auth-error key-status">
                        ⚠ This key is different from the one you saw for them before (
                        <code>{candidate.status.previousFingerprint}</code>). Accounts here can't change keys, so
                        this may mean the server is trying to intercept the file. Don't share unless they've
                        confirmed the new fingerprint with you directly.
                      </p>
                      <label className="field-hint">
                        <input
                          id="confirm-key-change"
                          type="checkbox"
                          checked={acceptChangedKey}
                          onChange={(e) => setAcceptChangedKey(e.target.checked)}
                        />{' '}
                        I've confirmed the new fingerprint with {candidate.email}
                      </label>
                    </>
                  )}
                  <div className="share-form">
                    <button
                      onClick={() => handleGrant(f)}
                      disabled={shareBusy || (candidate.status.kind === 'changed' && !acceptChangedKey)}
                    >
                      Confirm &amp; share
                    </button>
                    <button onClick={() => setCandidate(null)} disabled={shareBusy}>
                      Cancel
                    </button>
                  </div>
                </div>
              )}
              {shareError && <p className="auth-error">{shareError}</p>}
              <ul className="share-list">
                {shares.map((s) => (
                  <li key={s.recipient_id}>
                    <span>
                      {s.recipient_email} <span className="field-hint">({s.permission})</span>
                    </span>
                    {s.permission !== 'owner' && (
                      <button onClick={() => handleRevoke(f, s.recipient_id)} disabled={shareBusy}>
                        Revoke
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
