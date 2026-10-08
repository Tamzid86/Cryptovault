import crypto from 'node:crypto';
import { chromium } from 'playwright';

const email = `e2e-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
const password = 'correct-horse-battery-staple';
const fileName = `reload-${Date.now()}.txt`;
const fileBase64 = crypto.randomBytes(1024).toString('base64');

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const consoleErrors = [];
page.on('pageerror', (err) => consoleErrors.push(String(err)));

async function readStoredIdentity() {
  return page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const req = indexedDB.open('cryptvault');
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains('identity')) return resolve(null);
          const get = db.transaction('identity').objectStore('identity').get('current');
          get.onsuccess = async () => {
            const v = get.result;
            if (!v) return resolve(null);
            let exportable = true;
            try {
              await crypto.subtle.exportKey('jwk', v.privateKey);
            } catch {
              exportable = false;
            }
            resolve({ email: v.email, extractable: v.privateKey.extractable, exportable });
          };
        };
      }),
  );
}

try {
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });

  await page.evaluate(
    ({ b64, name }) => {
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      const dt = new DataTransfer();
      dt.items.add(new File([bytes], name, { type: 'text/plain' }));
      const input = document.querySelector('input[type=file]');
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    },
    { b64: fileBase64, name: fileName },
  );
  await page.waitForFunction((n) => document.querySelector('.file-name')?.textContent === n, fileName, {
    timeout: 30000,
  });
  console.log('PASS: registered and uploaded a file');

  const cookies = await context.cookies('http://localhost:8000/api/v1/auth/refresh');
  const refreshCookie = cookies.find((c) => c.name === 'cv_refresh');
  if (!refreshCookie?.httpOnly || refreshCookie.sameSite !== 'Strict') {
    throw new Error(`Refresh cookie missing or not httpOnly+Strict: ${JSON.stringify(refreshCookie)}`);
  }
  const jsCookies = await page.evaluate(() => document.cookie);
  if (jsCookies.includes('cv_refresh')) throw new Error('Refresh cookie is readable from page JS');
  console.log('PASS: refresh token is an httpOnly, SameSite=Strict cookie invisible to page JS');

  const stored = await readStoredIdentity();
  if (!stored || stored.email !== email) throw new Error('Identity was not stored in IndexedDB');
  if (stored.extractable || stored.exportable) throw new Error('Stored private key is extractable');
  console.log('PASS: IndexedDB holds the private key as a non-extractable CryptoKey');

  await page.reload();
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  if (!(await page.textContent('body')).includes(email)) throw new Error('Wrong account after reload');
  await page.waitForFunction((n) => document.querySelector('.file-name')?.textContent === n, fileName, {
    timeout: 15000,
  });
  console.log('PASS: reload kept the session, and the restored key still decrypts the file name');

  await page.goto('http://localhost:5173/login');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  console.log('PASS: visiting /login while signed in goes straight to the dashboard');

  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  await page.waitForFunction(async () => {
    const dbs = await indexedDB.databases();
    return dbs.some((d) => d.name === 'cryptvault');
  });
  if (await readStoredIdentity()) throw new Error('Logout left the identity in IndexedDB');
  const after = (await context.cookies('http://localhost:8000/api/v1/auth/refresh')).find((c) => c.name === 'cv_refresh');
  if (after) throw new Error('Logout left the refresh cookie behind');

  await page.goto('http://localhost:5173/dashboard');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  console.log('PASS: logout cleared key + cookie; a reload afterwards lands on /login');

  if (consoleErrors.length) throw new Error(`Page errors: ${consoleErrors.join(' | ')}`);
} catch (err) {
  console.error('FAIL:', err.message);
  process.exitCode = 1;
} finally {
  await browser.close();
}
