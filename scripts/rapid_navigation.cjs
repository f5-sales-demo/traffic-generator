// Verify each rapid navigation against its declared rendered route or API outcome.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, '../suites/catalog.json'), 'utf8'));
const scenario = catalog.scenarios.find((item) => item.id === 'bot-simulation/04-rapid-browsing');
const navigation = scenario.navigation_contract;

function validOutcome(expectation, observation) {
  if (expectation.statuses && !expectation.statuses.includes(observation.status)) return false;
  if (!observation.urlMatches || !observation.contentMatches) return false;
  if (expectation.contentType && !observation.contentType.includes(expectation.contentType)) return false;
  return true;
}

function needsFreshDocument(url, documentResponse) {
  return Boolean(new URL(url).hash) && documentResponse?.status() !== 200;
}

async function verifyNavigation(page, response, route, identity, directory, freshDocumentResponse = false) {
  const expected = navigation.find((item) => item.path === route);
  if (!expected) throw new Error('Undeclared rapid navigation');
  const id = `ua-${identity}-route-${navigation.indexOf(expected)}`;
  if (response && [403, 429].includes(response.status())) {
    if (new URL(route, page.url()).hash && !freshDocumentResponse)
      throw new Error('blocked document cannot execute SPA route');
    await page.screenshot({ path: path.join(directory, `${id}.png`) });
    return {
      id,
      performed: new URL(page.url()).pathname === new URL(route, page.url()).pathname,
      rendered: false,
      mitigated: true,
      status: response.status(),
      fresh_document_response: freshDocumentResponse,
      response_path: response.url ? new URL(response.url()).pathname + new URL(response.url()).search : null,
      response_method: response.request ? response.request().method() : null,
      response_sha256: response.body
        ? crypto
            .createHash('sha256')
            .update(await response.body())
            .digest('hex')
        : null,
      expected_outcome: 'mitigation-candidate',
    };
  }
  if (expected.selector) await page.locator(expected.selector).first().waitFor({ state: 'visible', timeout: 15000 });
  await page.waitForFunction(
    ({ selector, terms }) => {
      const element = document.querySelector(selector || 'body');
      return element && terms.every((term) => element.innerText.includes(term));
    },
    { selector: expected.selector, terms: expected.text },
    { timeout: 15000 },
  );
  for (const control of expected.controls || [])
    await page.locator(control).waitFor({ state: 'attached', timeout: 15000 });
  const identityMatches = expected.identity_selector
    ? (await page.locator(expected.identity_selector).innerText()).includes(expected.identity_text[0])
    : true;
  const text = expected.selector
    ? await page.locator(expected.selector).first().innerText()
    : await page.locator('body').innerText();
  const actual = new URL(page.url());
  const observation = {
    status: response ? response.status() : null,
    contentType: response ? response.headers()['content-type'] || '' : '',
    urlMatches: actual.pathname + actual.search + actual.hash === (expected.redirect_path || route),
    contentMatches: identityMatches && expected.text.every((term) => text.includes(term)),
  };
  const item = {
    id,
    performed: observation.urlMatches,
    rendered: validOutcome(expected, observation),
    expected_outcome: expected.outcome,
    ...observation,
  };
  await page.screenshot({ path: path.join(directory, `${id}.png`) });
  return item;
}
module.exports = { navigation, validOutcome, verifyNavigation, needsFreshDocument };
