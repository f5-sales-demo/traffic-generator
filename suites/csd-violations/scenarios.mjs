const assertion = (field, operator, value) => ({ field, operator, value });
const positive = (field) => assertion(field, 'gt', 0);
const truthy = (field) => assertion(field, 'eq', true);
const terminal = (field) => assertion(field, 'oneOf', ['finished', 'blocked', 'failed', 'timed-out']);

const navigate = (name, route) => {
  const waitForByRoute = {
    '/#/login': [
      '#email, input[type="email"], input[name*="email" i], input[autocomplete="username"]',
      '#password, input[type="password"], input[autocomplete="current-password"]',
    ],
    '/#/register': ['#emailControl', '#passwordControl', '[name="securityQuestion"]', '#securityAnswerControl'],
    '/': ['body'],
  };
  return {
    name,
    op: 'navigate',
    route,
    waitFor: waitForByRoute[route],
    waitTimeoutMs: 15_000,
    assertions: [assertion('navigationStatus', 'gte', 200), assertion('navigationStatus', 'lt', 400)],
  };
};
const evaluate = (name, run, assertions) => ({
  name,
  op: 'evaluate',
  run,
  assertions,
});
const loginObservation = (name = 'observe-login-fields') =>
  evaluate(name, () => window.__csdSim.observeFields(['email', 'password']), [positive('observedFieldCount')]);
const syntheticLogin = (name = 'set-synthetic-login-values') =>
  evaluate(name, () => window.__csdSim.setSyntheticLogin(), [
    assertion('setCount', 'eq', 2),
    assertion('markerCount', 'eq', 2),
    truthy('syntheticOnly'),
  ]);
const syntheticRegistration = (name = 'set-synthetic-registration-values') =>
  evaluate(name, () => window.__csdSim.setSyntheticRegistration(), [
    positive('setCount'),
    positive('markerCount'),
    truthy('syntheticOnly'),
  ]);
const multiCdn = (name = 'inject-four-cdn-candidates') =>
  evaluate(name, () => window.__csdSim.injectReviewedScripts(), [
    assertion('candidateCount', 'eq', 4),
    terminal('jsdelivr'),
    terminal('esm'),
    terminal('unpkg'),
    terminal('jspm'),
  ]);
const multiChannel = (name = 'attempt-three-benign-channels') =>
  evaluate(name, () => window.__csdSim.attemptChannels(), [
    assertion('channelCount', 'eq', 3),
    terminal('fetchPost'),
    truthy('imageAttempted'),
    truthy('prefetchAttempted'),
  ]);
const banner = (name = 'install-run-banner') =>
  evaluate(name, () => window.__csdSim.installBanner(), [truthy('installed')]);
const cleanupStep = (name = 'cleanup-run-artifacts') => ({
  name,
  op: 'cleanup',
  run: () => window.__csdSim.cleanupPage(),
  assertions: [
    assertion('artifactCount', 'eq', 0),
    assertion('managedControlValueCount', 'eq', 0),
    assertion('sensitiveValueCount', 'eq', 0),
    assertion('timerCount', 'eq', 0),
    assertion('listenerAttached', 'eq', false),
  ],
});

export const REVIEWED_DESTINATIONS = Object.freeze([
  'www.httpbin.org',
  'jsonplaceholder.typicode.com',
  'cdn.jsdelivr.net',
  'esm.sh',
  'unpkg.com',
  'ga.jspm.io',
]);

const manifestDefaults = Object.freeze({
  category: 'Client-Side Defense synthetic violation simulation',
  preconditions: Object.freeze([
    'Run only against the exact allowlisted HTTPS demo host.',
    'Use the deployed AWS worker with headed Chrome under Xvfb.',
    'Use only the reviewed benign external destinations declared by this manifest.',
  ]),
  syntheticDataPolicy: Object.freeze({
    markerAttribute: 'data-csd-synthetic',
    values: 'Fixed non-personal example values only; never source user, customer, browser-storage, or credential data.',
    lifecycle: 'Set through native DOM setters, then clear and mark every form control before each screenshot.',
  }),
  screenshotRequirement:
    'Capture every setup, action, assertion, cleanup, and final state after clearing and masking form controls; any failure fails the scenario.',
  claimBoundary:
    'Execution evidence shows browser activity only; it does not prove an F5 Distributed Cloud detection or classification.',
});

const scenario = ({ displayName, immediateEvidence, cleanup, destinations = [], ...definition }) =>
  Object.freeze({
    ...definition,
    displayName,
    category: manifestDefaults.category,
    preconditions: manifestDefaults.preconditions,
    syntheticDataPolicy: manifestDefaults.syntheticDataPolicy,
    immediateEvidence,
    cleanup,
    destinations: Object.freeze(destinations),
    screenshotRequirement: manifestDefaults.screenshotRequirement,
    claimBoundary: manifestDefaults.claimBoundary,
  });

const scenarios = [
  scenario({
    name: 'login-credential-skimmer',
    displayName: 'Login credential field observation',
    immediateEvidence:
      'Synthetic-marked native input updates, observed field count, and counter-only POST terminal state.',
    cleanup: 'Synthetic values are cleared before every screenshot; browser context is destroyed after the scenario.',
    destinations: ['www.httpbin.org'],
    steps: [
      navigate('navigate-login', '/#/login'),
      syntheticLogin(),
      loginObservation(),
      evaluate(
        'post-login-field-counters',
        () =>
          window.__csdSim.counterPost('https://www.httpbin.org/post', {
            observedFieldCount: 2,
          }),
        [assertion('postedCount', 'eq', 2), terminal('terminal')],
      ),
      cleanupStep('cleanup-login-controls'),
    ],
  }),
  scenario({
    name: 'registration-harvester',
    displayName: 'Registration control observation',
    immediateEvidence:
      'Synthetic-marked native registration updates, observed control count, and counter-only POST terminal state.',
    cleanup: 'Synthetic values are cleared before every screenshot; browser context is destroyed after the scenario.',
    destinations: ['jsonplaceholder.typicode.com'],
    steps: [
      navigate('navigate-registration', '/#/register'),
      syntheticRegistration(),
      evaluate('observe-registration-controls', () => window.__csdSim.observeControls(), [
        positive('observedControlCount'),
      ]),
      evaluate(
        'post-registration-control-counter',
        () =>
          window.__csdSim.counterPost('https://jsonplaceholder.typicode.com/posts', {
            observedControlCount: document.querySelectorAll('input,select,textarea').length,
          }),
        [positive('postedCount'), terminal('terminal')],
      ),
      cleanupStep('cleanup-registration-controls'),
    ],
  }),
  scenario({
    name: 'payment-overlay-card-skimmer',
    displayName: 'Masked payment overlay',
    immediateEvidence: 'Original-control count, value-free masked overlay state, and counter-only POST terminal state.',
    cleanup: 'Remove the synthetic overlay and clear page controls before evidence capture.',
    destinations: ['www.httpbin.org'],
    steps: [
      navigate('navigate-login', '/#/login'),
      evaluate('count-original-login-fields', () => window.__csdSim.observeControls(), [
        positive('observedControlCount'),
      ]),
      evaluate('install-masked-payment-overlay', () => window.__csdSim.installPaymentOverlay(), [
        truthy('installed'),
        truthy('maskedDisplayOnly'),
      ]),
      evaluate('post-payment-field-counter', () => window.__csdSim.postOriginalPaymentFieldCounter(), [
        positive('postedCount'),
        terminal('terminal'),
      ]),
      cleanupStep('cleanup-payment-overlay'),
    ],
  }),
  scenario({
    name: 'obfuscated-loader',
    displayName: 'Reviewed obfuscated loader',
    immediateEvidence: 'Decoded byte count and terminal load state for the fixed reviewed URL.',
    cleanup: 'Remove every injected node and timer before the final screenshot.',
    destinations: ['cdn.jsdelivr.net'],
    steps: [
      navigate('navigate-home', '/'),
      evaluate('decode-and-inject-reviewed-url', () => window.__csdSim.injectObfuscatedLoader(), [
        positive('decodedBytes'),
        terminal('terminal'),
      ]),
      cleanupStep('cleanup-obfuscated-loader'),
    ],
  }),
  scenario({
    name: 'multi-cdn-injection',
    displayName: 'Reviewed multi-CDN injection',
    immediateEvidence: 'Four candidate attempts and a terminal state for each reviewed CDN.',
    cleanup: 'Remove every injected script and timer before the final screenshot.',
    destinations: ['cdn.jsdelivr.net', 'esm.sh', 'unpkg.com', 'ga.jspm.io'],
    steps: [navigate('navigate-home', '/'), multiCdn(), cleanupStep('cleanup-multi-cdn-candidates')],
  }),
  scenario({
    name: 'tag-manager-hijack',
    displayName: 'Synthetic tag-manager candidate',
    immediateEvidence: 'Reviewed script terminal state and synthetic tag-manager marker.',
    cleanup: 'Remove the injected candidate before the final screenshot.',
    destinations: ['cdn.jsdelivr.net'],
    steps: [
      navigate('navigate-home', '/'),
      evaluate('inject-reviewed-tag-manager-candidate', () => window.__csdSim.installTagManagerCandidate(), [
        truthy('tagged'),
        terminal('terminal'),
      ]),
      cleanupStep('cleanup-tag-manager-candidate'),
    ],
  }),
  scenario({
    name: 'multi-channel-exfiltration',
    displayName: 'Counter-only multi-channel attempt',
    immediateEvidence: 'Terminal fetch state plus image and prefetch attempt flags; no field values are transmitted.',
    cleanup: 'Clear synthetic controls and remove injected image/link nodes before final capture.',
    destinations: ['www.httpbin.org', 'jsonplaceholder.typicode.com', 'cdn.jsdelivr.net'],
    steps: [
      navigate('navigate-login', '/#/login'),
      syntheticLogin(),
      loginObservation(),
      multiChannel(),
      cleanupStep('cleanup-multi-channel-artifacts'),
    ],
  }),
  scenario({
    name: 'high-volume-domain-exfiltration',
    displayName: 'Bounded multi-domain attempt',
    immediateEvidence: 'Exactly five reviewed script attempts, two counter-only POSTs, and seven terminal states.',
    cleanup: 'Remove injected nodes and timers before final capture.',
    destinations: REVIEWED_DESTINATIONS,
    steps: [
      navigate('navigate-login', '/#/login'),
      evaluate('attempt-five-scripts-two-posts', () => window.__csdSim.highVolumeAttempts(), [
        assertion('attemptCount', 'eq', 7),
        assertion('scriptCount', 'eq', 5),
        assertion('postCount', 'eq', 2),
        assertion('terminalCount', 'eq', 7),
        terminal('outcomes.scriptJsdelivr'),
        terminal('outcomes.scriptEsm'),
        terminal('outcomes.scriptUnpkg'),
        terminal('outcomes.scriptJspm'),
        terminal('outcomes.scriptChartjs'),
        terminal('outcomes.postHttpbin'),
        terminal('outcomes.postJsonplaceholder'),
      ]),
      cleanupStep('cleanup-high-volume-artifacts'),
    ],
  }),
  scenario({
    name: 'form-overlay',
    displayName: 'Value-free synthetic form overlay',
    immediateEvidence: 'Original-control count and synthetic overlay installation/geometry flags.',
    cleanup: 'Remove the synthetic overlay and clear all controls before capture.',
    steps: [
      navigate('navigate-login', '/#/login'),
      evaluate('count-original-fields-and-install-overlay', () => window.__csdSim.installFormOverlay(), [
        positive('originalFieldCount'),
        truthy('installed'),
        truthy('hasGeometry'),
      ]),
      cleanupStep('cleanup-form-overlay'),
    ],
  }),
  scenario({
    name: 'keylogger-simulation',
    displayName: 'Synthetic key-event counter',
    immediateEvidence:
      'Aggregate synthetic event count and explicit listener/timer cleanup flags; no key values are retained.',
    cleanup: 'Detach the listener, clear timers, clear form controls, and destroy the browser context.',
    steps: [
      navigate('navigate-login', '/#/login'),
      evaluate('count-synthetic-key-events', () => window.__csdSim.runKeyCounter(5), [
        assertion('eventCount', 'eq', 5),
        truthy('listenerDetached'),
        truthy('timerCleared'),
      ]),
      cleanupStep('cleanup-keylogger-artifacts'),
    ],
  }),
  scenario({
    name: 'maximum-detection',
    displayName: 'Combined bounded detection candidate',
    immediateEvidence:
      'Synthetic field observation, four reviewed CDN terminals, three channel attempts, and banner lifecycle.',
    cleanup: 'Clear synthetic controls and remove all injected artifacts before final capture.',
    destinations: REVIEWED_DESTINATIONS,
    steps: [
      navigate('navigate-login', '/#/login'),
      syntheticLogin('canonical-synthetic-login'),
      loginObservation('canonical-field-observation'),
      multiCdn('canonical-multi-cdn'),
      multiChannel('canonical-multi-channel'),
      banner('canonical-banner'),
      cleanupStep('cleanup-maximum-artifacts'),
    ],
  }),
];

export const SCENARIO_NAMES = Object.freeze(scenarios.map(({ name }) => name));
export const SCENARIOS = Object.freeze(scenarios);
export const SUITE_MANIFEST = Object.freeze({
  schemaVersion: '1.0.0',
  name: 'csd-violations',
  displayName: 'Client-Side Defense Synthetic Violation Scenarios',
  category: manifestDefaults.category,
  preconditions: manifestDefaults.preconditions,
  syntheticDataPolicy: manifestDefaults.syntheticDataPolicy,
  immediateEvidence:
    'Each step records its direct assertion result, bounded network terminal states, and a sanitized screenshot.',
  cleanup:
    'Each scenario has an asserted, screenshotted cleanup step that removes run-scoped artifacts and clears controls; final cleanup remains a safety net before the final screenshot, context close, and Chrome close.',
  destinations: REVIEWED_DESTINATIONS,
  screenshotRequirement: manifestDefaults.screenshotRequirement,
  claimBoundary: manifestDefaults.claimBoundary,
  scenarios: SCENARIOS,
});
