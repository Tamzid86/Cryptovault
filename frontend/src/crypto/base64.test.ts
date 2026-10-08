import { describe, expect, it } from 'vitest';
import { fromBase64, toBase64 } from './base64';

describe('base64 helpers', () => {
  it('round-trips arbitrary binary data, including zero bytes', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64));
    bytes[0] = 0;
    bytes[1] = 255;
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });

  it('round-trips an empty array', () => {
    expect(fromBase64(toBase64(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });
});
