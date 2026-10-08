export interface StoredIdentity {
  email: string;
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

export interface PinnedContact {
  fingerprint: string;
  firstSeen: string; // ISO timestamp
}

const DB_NAME = 'cryptvault';
const IDENTITY = 'identity';
const CONTACTS = 'contacts';
const IDENTITY_KEY = 'current';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDENTITY)) db.createObjectStore(IDENTITY);
      if (!db.objectStoreNames.contains(CONTACTS)) db.createObjectStore(CONTACTS);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(store: string, mode: IDBTransactionMode, op: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = op(db.transaction(store, mode).objectStore(store));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export function saveIdentity(identity: StoredIdentity): Promise<void> {
  return run(IDENTITY, 'readwrite', (s) => s.put(identity, IDENTITY_KEY));
}

export async function loadIdentity(): Promise<StoredIdentity | null> {
  return (await run<StoredIdentity | undefined>(IDENTITY, 'readonly', (s) => s.get(IDENTITY_KEY))) ?? null;
}

export function clearIdentity(): Promise<void> {
  return run(IDENTITY, 'readwrite', (s) => s.delete(IDENTITY_KEY));
}

const contactKey = (owner: string, contact: string) => `${owner.toLowerCase()}|${contact.toLowerCase()}`;

export async function getPinnedContact(owner: string, contact: string): Promise<PinnedContact | null> {
  return (await run<PinnedContact | undefined>(CONTACTS, 'readonly', (s) => s.get(contactKey(owner, contact)))) ?? null;
}

export function pinContact(owner: string, contact: string, pinned: PinnedContact): Promise<void> {
  return run(CONTACTS, 'readwrite', (s) => s.put(pinned, contactKey(owner, contact)));
}
