import type { Identity } from '../auth/authState';
import type { FileSummary } from '../api/files';
import { createShare } from '../api/files';
import { lookupUser } from '../api/users';
import { getPinnedContact, pinContact } from '../auth/keyStore';
import { toBase64, fromBase64 } from '../crypto/base64';
import { exportKey } from '../crypto/aes';
import { fingerprint } from '../crypto/fingerprint';
import { wrapFileKey } from '../crypto/wrap';
import { unwrapFileKeyForSummary } from './fileKey';

export type KeyStatus =
  | { kind: 'new' }
  | { kind: 'match'; since: string }
  | { kind: 'changed'; previousFingerprint: string; since: string };

export interface ShareCandidate {
  email: string;
  publicKey: Uint8Array;
  fingerprint: string;
  status: KeyStatus;
}

export async function prepareShare(recipientEmail: string, identity: Identity): Promise<ShareCandidate> {
  const recipient = await lookupUser(recipientEmail);
  const publicKey = fromBase64(recipient.public_key);
  const fp = await fingerprint(publicKey);

  const pinned = await getPinnedContact(identity.email, recipient.email).catch(() => null);
  let status: KeyStatus = { kind: 'new' };
  if (pinned && pinned.fingerprint === fp) status = { kind: 'match', since: pinned.firstSeen };
  else if (pinned) status = { kind: 'changed', previousFingerprint: pinned.fingerprint, since: pinned.firstSeen };

  return { email: recipient.email, publicKey, fingerprint: fp, status };
}

export async function shareFileWithUser(f: FileSummary, candidate: ShareCandidate, identity: Identity): Promise<void> {
  const fileKey = await unwrapFileKeyForSummary(f, identity);
  const fileKeyRaw = await exportKey(fileKey);
  const wrapped = await wrapFileKey(candidate.publicKey, fileKeyRaw);

  await createShare(f.id, {
    recipient_email: candidate.email,
    ephemeral_public_key: toBase64(wrapped.ephemeralPublicKey),
    wrapped_key: toBase64(wrapped.ciphertext),
    wrap_nonce: toBase64(wrapped.nonce),
  });

  if (candidate.status.kind !== 'match') {
    await pinContact(identity.email, candidate.email, {
      fingerprint: candidate.fingerprint,
      firstSeen: new Date().toISOString(),
    }).catch(() => {});
  }
}
