#!/usr/bin/env node
// Automated form filling simulation
// Tools: playwright
// Targets: Juice Shop registration and contact forms
// Estimated duration: 1-2 minutes

const { chromium } = require('playwright');
const path = require('node:path');
const fs = require('node:fs');
const PROFILE_DIR = `/tmp/pw-profile-${path.basename(__filename, '.js')}-${process.pid}`;
process.on('exit', () => {
  try {
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  } catch {}
});

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 03-headless-form-fill.js <TARGET_FQDN>');
  process.exit(1);
}

const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;

// Fake identities for form filling
const IDENTITIES = [
  {
    email: 'bot1@spam.example',
    password: 'BotPass1!',
    name: 'Bot User One',
    comment: 'Great products, buy now at spam.example',
  },
  {
    email: 'bot2@spam.example',
    password: 'BotPass2!',
    name: 'Bot User Two',
    comment: 'Check out these deals at phishing.example',
  },
  {
    email: 'bot3@spam.example',
    password: 'BotPass3!',
    name: 'Bot User Three',
    comment: 'Free gift cards at malware.example',
  },
  { email: 'bot4@spam.example', password: 'BotPass4!', name: 'Bot User Four', comment: 'You won a prize, click here' },
  {
    email: 'bot5@spam.example',
    password: 'BotPass5!',
    name: 'Bot User Five',
    comment: 'Earn money from home at scam.example',
  },
  {
    email: 'bot6@spam.example',
    password: 'BotPass6!',
    name: 'Bot User Six',
    comment: 'Hot singles in your area at phish.example',
  },
  {
    email: 'bot7@spam.example',
    password: 'BotPass7!',
    name: 'Bot User Seven',
    comment: 'Crypto investment at ponzi.example',
  },
  {
    email: 'bot8@spam.example',
    password: 'BotPass8!',
    name: 'Bot User Eight',
    comment: 'Congratulations winner at 419.example',
  },
];

(async () => {
  console.log(`[*] Automated form filling against ${TARGET_FQDN}`);
  console.log(`[*] Using ${IDENTITIES.length} bot identities`);
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors'],
  });

  let registrations = 0;
  let contacts = 0;

  for (const identity of IDENTITIES.slice(0, Number(process.env.TGEN_BROWSER_IDENTITIES || IDENTITIES.length))) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);

    // --- Registration form ---
    try {
      console.log(`[+] Registering: ${identity.email}`);
      await page.goto(`${BASE_URL}/juice-shop/#/register`, {
        waitUntil: 'domcontentloaded',
        timeout: 15000,
      });

      await page.fill('#emailControl', identity.email);
      await page.fill('#passwordControl', identity.password);
      await page.fill('#repeatPasswordControl', identity.password);

      // Select security question
      await page.click('[name="securityQuestion"]').catch(() => {});
      await page.waitForTimeout(500);
      const options = await page.$$('mat-option');
      if (options.length > 0) {
        await options[0].click();
      }
      await page.fill('#securityAnswerControl', 'bot answer');

      await page.click('#registerButton').catch(() => {});
      await page.waitForTimeout(1000);
      console.log(`    Registration submitted`);
      registrations++;
    } catch (err) {
      console.log(`    Registration error: ${err.message}`);
    }

    // --- Contact form ---
    try {
      console.log(`[+] Submitting contact form as: ${identity.name}`);
      await page.goto(`${BASE_URL}/juice-shop/#/contact`, {
        waitUntil: 'domcontentloaded',
        timeout: 15000,
      });

      await page.fill('#comment', identity.comment);

      // Set rating
      const stars = await page.$$('.br-unit');
      if (stars.length > 0) {
        await stars[stars.length - 1].click();
      }

      await page.click('#submitButton').catch(() => {});
      await page.waitForTimeout(500);
      console.log(`    Contact form submitted`);
      contacts++;
    } catch (err) {
      console.log(`    Contact form error: ${err.message}`);
    }

    await context.close();
    console.log('');
  }

  await browser.close();
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  console.log('[*] Form filling simulation complete');
  console.log(`    Registrations attempted: ${registrations}`);
  console.log(`    Contact forms submitted: ${contacts}`);
})();
