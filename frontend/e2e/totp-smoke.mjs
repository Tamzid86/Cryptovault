import crypto from 'node:crypto';
import { chromium } from 'playwright';

function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32.replace(/=+$/, '').toUpperCase()) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totp(secretBase32, { timeStep = 30, digits = 6, forTimeMs = Date.now() } = {}) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(forTimeMs / 1000 / timeStep);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (binCode % 10 ** digits).toString().padStart(digits, '0');
}

const email = `totp-${Date.now()}@example.com`;
const password = 'correct-horse-battery-staple';

const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') errors.push(msg.text());
});
page.on('pageerror', (err) => errors.push(String(err)));

try {
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  console.log('PASS: registered and reached dashboard');

  await page.click('text=Security');
  await page.waitForSelector('text=Set up authenticator app', { timeout: 10000 });
  await page.click('text=Set up authenticator app');
  await page.waitForSelector('.identity-card code', { timeout: 10000 });
  const secret = await page.textContent('.identity-card code');
  console.log('PASS: TOTP setup returned a secret and QR code');

  await page.fill('input[inputmode=numeric]', totp(secret));
  await page.click('text=Verify & enable');
  await page.waitForSelector('text=Enabled.', { timeout: 10000 });
  console.log('PASS: TOTP verified and enabled');

  await page.click('text=Back to files');
  await page.waitForSelector('.dashboard-header', { timeout: 10000 });
  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');

  await page.waitForSelector("text=Verify it's you", { timeout: 10000 });
  console.log('PASS: login now requires a second factor');

  await page.fill('#totp', totp(secret));
  await page.click('button:has-text("Verify")');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  console.log('PASS: TOTP code completed login, reached dashboard');

  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector("text=Verify it's you", { timeout: 10000 });
  await page.fill('#totp', '000000');
  await page.click('button:has-text("Verify")');
  await page.waitForSelector('.auth-error', { timeout: 10000 });
  console.log('PASS: wrong TOTP code rejected at login');

  const unexpectedErrors = errors.filter((e) => !e.includes('401'));
  if (unexpectedErrors.length) {
    console.log('Unexpected console errors during run:', unexpectedErrors);
    process.exitCode = 1;
  } else {
    console.log('No unexpected console/page errors during the run.');
  }
} catch (err) {
  console.error('FAIL:', err);
  console.error('Console errors seen:', errors);
  process.exitCode = 1;
} finally {
  await browser.close();
}
