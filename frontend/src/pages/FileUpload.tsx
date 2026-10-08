import axios from 'axios';
import { useRef, useState, type ChangeEvent } from 'react';
import { useAuth } from '../auth/authState';
import { uploadFile } from '../files/upload';

export function FileUpload({ onUploaded }: { onUploaded: () => void }) {
  const { identity } = useAuth();
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  async function handleChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !identity) return;

    setBusy(true);
    setError(null);
    setProgress(0);
    try {
      await uploadFile(file, identity, setProgress);
      onUploaded();
    } catch (err) {
      const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null;
      setError(typeof detail === 'string' ? detail : 'Upload failed');
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  }

  return (
    <div className="upload-card">
      <label className="upload-button">
        {busy ? `Encrypting & uploading… ${Math.round(progress * 100)}%` : 'Upload file'}
        <input ref={inputRef} type="file" onChange={handleChange} disabled={busy} hidden />
      </label>
      {error && <p className="auth-error">{error}</p>}
    </div>
  );
}
