import { chromium } from 'playwright';

const password = 'correct-horse-battery-staple';
const freshEmail = () => `e2e-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;

const browser = await chromium.launch();

async function registerOnNewPage() {
  const page = await browser.newPage();
  const email = freshEmail();
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  return page;
}

try {
  {
    const page = await browser.newPage();
    let injected = false;
    const filesAuthHeaders = [];
    let refreshCalls = 0;

    await page.route('**/api/v1/files', async (route) => {
      filesAuthHeaders.push(route.request().headers()['authorization']);
      if (!injected) {
        injected = true;
        await route.fulfill({ status: 401, contentType: 'application/json', body: '{"detail":"expired"}' });
      } else {
        await route.continue();
      }
    });
    page.on('request', (req) => {
      if (req.url().endsWith('/api/v1/auth/refresh') && req.method() === 'POST') refreshCalls++;
    });

    await page.goto('http://localhost:5173/register');
    await page.fill('#email', freshEmail());
    await page.fill('#password', password);
    const filesOk = page.waitForResponse(
      (r) =>
        r.url().endsWith('/api/v1/files') &&
        r.status() === 200 &&
        r.request().headers()['authorization'] !== filesAuthHeaders[0],
      { timeout: 15000 },
    );
    await page.click('button[type=submit]');
    await page.waitForSelector('.dashboard-header', { timeout: 15000 });
    await filesOk;

    if (refreshCalls !== 1) throw new Error(`Expected exactly 1 refresh call, saw ${refreshCalls}`);
    if (!filesAuthHeaders.some((h) => h !== filesAuthHeaders[0])) {
      throw new Error('Retried /files request did not carry a new access token');
    }
    if (!(await page.isVisible('.dashboard-header'))) throw new Error('User was logged out despite successful refresh');
    console.log('PASS: 401 triggered one refresh, request retried with new token, session kept');
    await page.close();
  }

  {
    const page = await registerOnNewPage();
    await page.route('**/api/v1/files', (route) =>
      route.fulfill({ status: 401, contentType: 'application/json', body: '{"detail":"expired"}' }),
    );
    await page.route('**/api/v1/auth/refresh', (route) =>
      route.fulfill({ status: 401, contentType: 'application/json', body: '{"detail":"expired"}' }),
    );

    await page.setInputFiles('input[type=file]', {
      name: 'x.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from('hello'),
    });
    await page.waitForSelector('.auth-form', { timeout: 10000 });
    console.log('PASS: rejected refresh token logged the user out to /login');
    await page.close();
  }
} catch (err) {
  console.error('FAIL:', err.message);
  process.exitCode = 1;
} finally {
  await browser.close();
}
