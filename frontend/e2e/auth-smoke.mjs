import { chromium } from 'playwright';

const email = `e2e-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
const password = 'correct-horse-battery-staple';

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
  const bodyAfterRegister = await page.textContent('body');
  if (!bodyAfterRegister.includes(email)) throw new Error('Dashboard did not show registered email after register+auto-login');
  console.log('PASS: register -> auto-login -> dashboard');

  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });

  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  const bodyAfterLogin = await page.textContent('body');
  if (!bodyAfterLogin.includes(email)) throw new Error('Dashboard did not show email after fresh login');
  console.log('PASS: logout -> login -> dashboard (private key decrypted correctly)');

  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  await page.fill('#email', email);
  await page.fill('#password', 'totally-wrong-password');
  await page.click('button[type=submit]');
  await page.waitForSelector('.auth-error', { timeout: 10000 });
  const errorText = await page.textContent('.auth-error');
  console.log(`PASS: wrong password rejected with error: "${errorText}"`);

  await page.goto('http://localhost:5173/dashboard');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  console.log('PASS: unauthenticated access to /dashboard redirects to /login');

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
