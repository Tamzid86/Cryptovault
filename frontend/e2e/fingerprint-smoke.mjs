import crypto from 'node:crypto';
import { chromium } from 'playwright';

const password = 'correct-horse-battery-staple';
const stamp = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
const alice = `e2e-alice-${stamp}@example.com`;
const bob = `e2e-bob-${stamp}@example.com`;
const fileName = `fp-${stamp}.txt`;

const browser = await chromium.launch();
const pageErrors = [];

async function register(email) {
  const page = await browser.newPage();
  page.on('pageerror', (err) => pageErrors.push(String(err)));
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  return page;
}

async function lookUp(page, email) {
  await page.fill('.share-form input[type=email]', email);
  await page.click('.share-form button:has-text("Look up")');
  await page.waitForSelector('.share-confirm', { timeout: 10000 });
  return page.getAttribute('.share-confirm', 'data-status');
}

async function shareAndRevoke(page, email) {
  await page.click('.share-confirm button:has-text("Confirm & share")');
  await page.waitForSelector(`.share-list li:has-text("${email}")`, { timeout: 10000 });
  await page.click(`.share-list li:has-text("${email}") button:has-text("Revoke")`);
  await page.waitForSelector(`.share-list li:has-text("${email}")`, { state: 'detached', timeout: 10000 });
}

try {
  const alicePage = await register(alice);
  const bobPage = await register(bob);

  const bobFingerprint = await bobPage.textContent('.my-fingerprint');
  if (!/^([0-9A-F]{4} ){7}[0-9A-F]{4}$/.test(bobFingerprint)) throw new Error(`Bad fingerprint format: ${bobFingerprint}`);
  if ((await bobPage.textContent('body')).match(/[A-Za-z0-9+/]{43}=/)) throw new Error('Raw public key still shown');
  console.log(`PASS: dashboard shows a short fingerprint (${bobFingerprint}), not the raw key`);

  await alicePage.evaluate((name) => {
    const dt = new DataTransfer();
    dt.items.add(new File(['fingerprint test'], name, { type: 'text/plain' }));
    const input = document.querySelector('input[type=file]');
    input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, fileName);
  await alicePage.waitForFunction((n) => document.querySelector('.file-name')?.textContent === n, fileName, {
    timeout: 30000,
  });
  await alicePage.click('.file-row button:has-text("Share")');

  if ((await lookUp(alicePage, bob)) !== 'new') throw new Error('First lookup should be "new"');
  await shareAndRevoke(alicePage, bob);
  console.log('PASS: first share shows "new" and pins Bob\'s key');

  if ((await lookUp(alicePage, bob)) !== 'match') throw new Error('Second lookup should be "match"');
  console.log('PASS: sharing again recognises the same key');
  await alicePage.click('.share-confirm button:has-text("Cancel")');

  const attackerKey = crypto.randomBytes(32).toString('base64');
  await alicePage.route('**/api/v1/users/lookup**', async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    await route.fulfill({ response: res, json: { ...body, public_key: attackerKey } });
  });
  if ((await lookUp(alicePage, bob)) !== 'changed') throw new Error('Swapped key should be flagged "changed"');
  const shown = await alicePage.textContent('.recipient-fingerprint');
  if (shown === bobFingerprint) throw new Error("Swapped key shows Bob's real fingerprint");
  const confirmBtn = '.share-confirm button:has-text("Confirm & share")';
  if (!(await alicePage.isDisabled(confirmBtn))) throw new Error('Confirm should be disabled for a changed key');
  await alicePage.check('#confirm-key-change');
  if (await alicePage.isDisabled(confirmBtn)) throw new Error('Confirm should enable after explicit acceptance');
  console.log('PASS: a swapped key is flagged, and sharing is blocked until explicitly accepted');

  await alicePage.click('.share-confirm button:has-text("Cancel")');
  if (await alicePage.$(`.share-list li:has-text("${bob}")`)) throw new Error('Cancel still shared the file');
  console.log('PASS: cancelling shares nothing');

  if (pageErrors.length) throw new Error(`Page errors: ${pageErrors.join(' | ')}`);
} catch (err) {
  console.error('FAIL:', err.message);
  process.exitCode = 1;
} finally {
  await browser.close();
}
