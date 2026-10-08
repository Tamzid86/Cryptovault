export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(publicKey)));
  const hex = Array.from(digest.slice(0, 16), (b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return hex.match(/.{4}/g)!.join(' ');
}
