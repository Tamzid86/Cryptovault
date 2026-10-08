import crypto from 'node:crypto';
import { chromium } from 'playwright';

const email = `e2e-file-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
const password = 'correct-horse-battery-staple';
const fileName = 'secret-plans.txt';
const fileBytes = crypto.randomBytes(9 * 1024 * 1024); // spans 3 chunks at 4 MiB each
const fileBase64 = fileBytes.toString('base64');
const fileSha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');

const browser = await chromium.launch();
const page = await browser.newPage();
const consoleErrors = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') consoleErrors.push(msg.text());
});
page.on('pageerror', (err) => consoleErrors.push(String(err)));

try {
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  console.log('PASS: registered and reached dashboard');

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

  await page.waitForSelector('.file-row', { timeout: 60000 });
  console.log('PASS: upload completed, file row appeared');

  await page.waitForFunction(
    (name) => document.querySelector('.file-name')?.textContent === name,
    fileName,
    { timeout: 15000 },
  );
  console.log('PASS: filename decrypted correctly in the file list');

  const downloadPromise = page.waitForEvent('download', { timeout: 30000 });
  await page.click('.file-row button:has-text("Download")');
  const download = await downloadPromise;
  const downloadedPath = await download.path();

  const fs = await import('node:fs');
  const downloadedBytes = fs.readFileSync(downloadedPath);
  const downloadedSha256 = crypto.createHash('sha256').update(downloadedBytes).digest('hex');

  if (downloadedSha256 !== fileSha256) {
    throw new Error(`Downloaded file hash mismatch: expected ${fileSha256}, got ${downloadedSha256}`);
  }
  if (download.suggestedFilename() !== fileName) {
    throw new Error(`Downloaded filename mismatch: expected ${fileName}, got ${download.suggestedFilename()}`);
  }
  console.log('PASS: downloaded file is byte-identical to the original (sha256 match) across 3 chunks');

  await page.click('.file-row button:has-text("Delete")');
  await page.waitForSelector('text=No files yet.', { timeout: 10000 });
  console.log('PASS: delete removed the file from the list');

  const unexpectedErrors = consoleErrors;
  if (unexpectedErrors.length) {
    console.log('Unexpected console errors during run:', unexpectedErrors);
    process.exitCode = 1;
  } else {
    console.log('No unexpected console/page errors during the run.');
  }
} catch (err) {
  console.error('FAIL:', err);
  console.error('Console errors seen:', consoleErrors);
  process.exitCode = 1;
} finally {
  await browser.close();
}
