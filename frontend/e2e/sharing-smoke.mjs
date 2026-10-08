import crypto from 'node:crypto';
import { chromium } from 'playwright';

const stamp = Date.now();
const alice = { email: `alice-${stamp}@example.com`, password: 'correct-horse-battery-staple' };
const bob = { email: `bob-${stamp}@example.com`, password: 'correct-horse-battery-staple' };
const fileName = 'quarterly-report.txt';
const fileBytes = crypto.randomBytes(256 * 1024);
const fileBase64 = fileBytes.toString('base64');
const fileSha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');

const browser = await chromium.launch();
const errors = [];

function trackErrors(page, who) {
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(`[${who}] ${msg.text()}`);
  });
  page.on('pageerror', (err) => errors.push(`[${who}] ${err}`));
}

async function registerUser(page, user) {
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', user.email);
  await page.fill('#password', user.password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
}

async function relogin(page, user) {
  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  await page.fill('#email', user.email);
  await page.fill('#password', user.password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
}

async function uploadSampleFile(page) {
  await page.evaluate(
    ({ b64, name }) => {
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      const file = new File([bytes], name, { type: 'text/plain' });
      const dt = new DataTransfer();
      dt.items.add(file);
      const input = document.querySelector('input[type=file]');
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    },
    { b64: fileBase64, name: fileName },
  );
  await page.waitForSelector('.file-row', { timeout: 30000 });
}

try {
  const alicePage = await browser.newPage();
  const bobPage = await browser.newPage();
  trackErrors(alicePage, 'alice');
  trackErrors(bobPage, 'bob');

  await registerUser(alicePage, alice);
  console.log('PASS: Alice registered');
  await registerUser(bobPage, bob);
  console.log('PASS: Bob registered');

  await uploadSampleFile(alicePage);
  console.log('PASS: Alice uploaded a file');

  const bobBodyBefore = await bobPage.textContent('body');
  if (bobBodyBefore.includes(fileName)) throw new Error("Bob can see Alice's file before being shared with");
  console.log("PASS: Bob cannot see Alice's file before sharing");

  await alicePage.click('.file-row button:has-text("Share")');
  await alicePage.fill('.share-form input[type=email]', bob.email);
  await alicePage.click('.share-form button:has-text("Look up")');
  await alicePage.waitForSelector('.share-confirm[data-status="new"] .recipient-fingerprint', { timeout: 10000 });

  const seenByAlice = await alicePage.textContent('.recipient-fingerprint');
  const bobsOwn = await bobPage.textContent('.my-fingerprint');
  if (seenByAlice !== bobsOwn) throw new Error(`Fingerprint mismatch: Alice sees ${seenByAlice}, Bob has ${bobsOwn}`);
  console.log(`PASS: fingerprint Alice sees for Bob matches Bob's dashboard (${bobsOwn})`);

  await alicePage.click('.share-confirm button:has-text("Confirm & share")');
  await alicePage.waitForSelector(`.share-list li:has-text("${bob.email}")`, { timeout: 10000 });
  console.log('PASS: Alice granted Bob access, appears in share list');

  await relogin(bobPage, bob);
  await bobPage.waitForFunction(
    (name) => document.querySelector('.file-name')?.textContent === name,
    fileName,
    { timeout: 15000 },
  );
  console.log("PASS: Bob now sees Alice's file with the correct decrypted name");

  const bobRowHtml = await bobPage.locator('.file-row').first().innerHTML();
  if (bobRowHtml.includes('>Delete<') || bobRowHtml.includes('>Share<')) {
    throw new Error('Bob (read-only) sees owner-only Share/Delete controls');
  }
  console.log('PASS: Bob does not see Share/Delete controls (read-only RBAC)');

  const downloadPromise = bobPage.waitForEvent('download', { timeout: 20000 });
  await bobPage.click('.file-row button:has-text("Download")');
  const download = await downloadPromise;
  const fs = await import('node:fs');
  const downloadedBytes = fs.readFileSync(await download.path());
  const downloadedSha256 = crypto.createHash('sha256').update(downloadedBytes).digest('hex');
  if (downloadedSha256 !== fileSha256) throw new Error('Bob downloaded a file that does not match the original');
  console.log("PASS: Bob downloaded and decrypted Alice's file correctly (sha256 match)");

  await alicePage.click(`.share-list li:has-text("${bob.email}") button:has-text("Revoke")`);
  await alicePage.waitForFunction(
    (email) => !document.body.textContent.includes(email),
    bob.email,
    { timeout: 10000 },
  );
  console.log("PASS: Alice revoked Bob's access");

  await relogin(bobPage, bob);
  const bobBodyAfterRevoke = await bobPage.textContent('body');
  if (bobBodyAfterRevoke.includes(fileName)) throw new Error("Bob still sees Alice's file after revocation");
  console.log("PASS: Bob can no longer see Alice's file after revocation");

  if (errors.length) {
    console.log('Unexpected console errors during run:', errors);
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
