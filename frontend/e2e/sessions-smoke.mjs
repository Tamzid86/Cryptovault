import { chromium } from 'playwright';

const base = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const email = `e2e-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
const password = 'correct-horse-battery-staple';

const browser = await chromium.launch();
const contextOptions = { ignoreHTTPSErrors: true };
const deviceA = await (await browser.newContext(contextOptions)).newPage();
const deviceB = await (await browser.newContext(contextOptions)).newPage();
const consoleErrors = [];
for (const page of [deviceA, deviceB]) {
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(String(err)));
}

async function login(page) {
  await page.goto(`${base}/login`);
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 20000 });
}

try {
  await deviceA.goto(`${base}/register`);
  await deviceA.fill('#email', email);
  await deviceA.fill('#password', password);
  await deviceA.click('button[type=submit]');
  await deviceA.waitForSelector('.dashboard-header', { timeout: 20000 });
  console.log('PASS: registered on device A');

  await deviceA.waitForSelector('.storage-usage', { timeout: 10000 });
  const before = await deviceA.textContent('.storage-usage');
  if (!/0 B of 1\.0 GiB used/.test(before)) throw new Error(`Unexpected initial storage readout: "${before}"`);

  await deviceA.setInputFiles('input[type=file]', {
    name: 'quota-check.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(3 * 1024, 7),
  });
  await deviceA.waitForSelector('text=quota-check.bin', { timeout: 20000 });
  await deviceA.waitForFunction(
    () => document.querySelector('.storage-usage')?.textContent?.includes('3.0 KiB of 1.0 GiB used'),
    null,
    { timeout: 10000 },
  );
  console.log('PASS: storage readout went from 0 B to 3.0 KiB after an upload');

  await login(deviceB);
  console.log('PASS: same account signed in on device B');

  await deviceA.goto(`${base}/security`);
  await deviceA.waitForSelector('text=Sign out everywhere', { timeout: 15000 });
  await deviceA.click('text=Sign out everywhere');
  await deviceA.waitForSelector('.auth-form', { timeout: 10000 });
  console.log('PASS: device A signed out everywhere and landed on /login');

  await deviceB.reload();
  await deviceB.waitForSelector('.auth-form', { timeout: 15000 });
  console.log("PASS: device B's session was revoked too -- its reload landed on /login");

  await login(deviceA);
  console.log('PASS: signing in again afterwards works normally');

  const unexpectedErrors = consoleErrors.filter((e) => !e.includes('401'));
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
