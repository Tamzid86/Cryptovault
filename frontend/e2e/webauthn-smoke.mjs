import { chromium } from 'playwright';

const email = `webauthn-${Date.now()}@example.com`;
const password = 'correct-horse-battery-staple';

const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') errors.push(msg.text());
});
page.on('pageerror', (err) => errors.push(String(err)));

const cdp = await page.context().newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
  },
});
console.log('PASS: virtual authenticator attached:', authenticatorId);

try {
  await page.goto('http://localhost:5173/register');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  console.log('PASS: registered and reached dashboard');

  await page.click('text=Security');
  await page.waitForSelector('text=Add a passkey', { timeout: 10000 });
  await page.click('text=Add a passkey');
  await page.waitForSelector('text=1 registered.', { timeout: 15000 });
  console.log('PASS: passkey registered via virtual authenticator, count updated');

  await page.click('text=Back to files');
  await page.waitForSelector('.dashboard-header', { timeout: 10000 });
  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });

  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector("text=Verify it's you", { timeout: 10000 });
  console.log('PASS: login requires MFA, offers passkey option');

  await page.click('text=Use a passkey');
  await page.waitForSelector('.dashboard-header', { timeout: 15000 });
  console.log('PASS: passkey assertion completed login, reached dashboard');

  await page.click('text=Log out');
  await page.waitForSelector('.auth-form', { timeout: 10000 });
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForSelector("text=Verify it's you", { timeout: 10000 });
  await page.click('text=Use a passkey');
  await page.waitForSelector('.auth-error', { timeout: 15000 });
  console.log('PASS: an unenrolled authenticator cannot complete login');

  const unexpectedErrors = errors.filter((e) => !e.includes('401') && !e.includes('400'));
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
