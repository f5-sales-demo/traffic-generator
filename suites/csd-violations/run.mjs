#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import browserRequests from '../../scripts/browser_requests.cjs';
import { DEFAULT_POLICY } from './continuous.mjs';
import {
  APPROVED_CSD_COLLECTORS,
  HEADER_SCENARIO_SELECTORS,
  HEADER_VALUES,
  PAYMENT_PATH,
  SCENARIOS,
  SELECTOR_HEADER,
  SUITE_MANIFEST,
} from './scenarios.mjs';

const EXPECTED_HOST = 'client-side-defense.f5-sales-demo.com';
const SENSOR_RE = /\/__imp_apg__\/js\//;
const DIP_RE = /\/__imp_apg__\/api\/dip/;
const REDACTED_URL_KEYS = new Set(['email', 'password', 'token', 'key', 'card', 'cookie', 'authorization']);

const httpStatus = (value) => (Number.isInteger(value) && value >= 100 && value <= 599 ? value : null);
const approvedDip = (rawUrl) => {
  try {
    const url = new URL(rawUrl);
    return (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      APPROVED_CSD_COLLECTORS.some(({ host, path }) => url.origin === `https://${host}` && url.pathname === path)
    );
  } catch {
    return false;
  }
};

// Compare raw bytes, not URL-normalized aliases. The selector never reaches assets or collectors.
export function selectorRequestAllowed(request, target, scope = 'same-origin') {
  if (!['document', 'same-origin'].includes(scope)) return false;
  try {
    const base = new URL(target);
    const rawUrl = typeof request.url === 'function' ? request.url() : request.url;
    const method = typeof request.method === 'function' ? request.method() : request.method;
    const type = typeof request.resourceType === 'function' ? request.resourceType() : request.resourceType;
    if (
      base.protocol !== 'https:' ||
      base.username ||
      base.password ||
      rawUrl !== `${base.origin}${PAYMENT_PATH}` ||
      (typeof request.redirectedFrom === 'function' ? request.redirectedFrom() : request.redirectedFrom) ||
      request.redirectedRequestId ||
      type === 'Preflight'
    )
      return false;
    return scope === 'document'
      ? method === 'GET' && ['Document', 'document'].includes(type)
      : ['GET', 'HEAD'].includes(method);
  } catch {
    return false;
  }
}

export function headerFacts(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return null;
  const facts = {};
  for (const [name, canonical] of Object.entries(HEADER_VALUES)) {
    const keys = Object.keys(headers).filter((key) => key.toLowerCase() === name);
    if (
      keys.length > 1 ||
      (keys.length === 1 && (typeof headers[keys[0]] !== 'string' || /[\r\n]/.test(headers[keys[0]])))
    )
      return null;
    facts[name] = { present: keys.length === 1, matchesCanonical: keys.length === 1 && headers[keys[0]] === canonical };
  }
  return facts;
}
const selectorFact = (headers, selector) => {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return null;
  const keys = Object.keys(headers).filter((key) => key.toLowerCase() === SELECTOR_HEADER.toLowerCase());
  if (keys.length > 1 || (keys.length && typeof headers[keys[0]] !== 'string')) return null;
  return { present: keys.length === 1, matchesSelected: keys.length === 1 && headers[keys[0]] === selector };
};

export function aggregateDipOutcomes(records) {
  const outcomes = { observed: 0, finished: 0, failed: 0, http2xx: 0, httpNon2xx: 0, statusUnknown: 0 };
  for (const record of records) {
    if (record.approvedDip !== true || record.method !== 'POST') continue;
    outcomes.observed++;
    if (record.terminal === 'finished') outcomes.finished++;
    if (['failed', 'blocked', 'timed-out'].includes(record.terminal)) outcomes.failed++;
    const status = httpStatus(record.status);
    if (status === null) outcomes.statusUnknown++;
    else if (status >= 200 && status < 300) outcomes.http2xx++;
    else outcomes.httpNon2xx++;
  }
  return outcomes;
}

// IDs, initiators and raw header maps stay private; only fixed booleans/counters escape.
export function createHeaderPairTracker(target, selector) {
  const groups = new Map();
  let invalid = false;
  const group = (id) => {
    if (typeof id !== 'string' || !id) {
      invalid = true;
      return null;
    }
    if (!groups.has(id)) {
      if (groups.size >= 512) {
        invalid = true;
        return null;
      }
      groups.set(id, {
        requests: [],
        requestExtras: [],
        responses: [],
        responseExtras: [],
        terminal: 'pending',
        terminalEvidence: { state: 'pending', canceled: false, errorCode: null, responseReceivedBeforeTerminal: false },
      });
    }
    return groups.get(id);
  };
  return {
    event(method, params = {}) {
      const g = group(params.requestId);
      if (!g) return;
      if ([g.requests, g.requestExtras, g.responses, g.responseExtras].some((entries) => entries.length >= 2)) {
        invalid = true;
        return;
      }
      if (method === 'Network.requestWillBeSent') {
        if (g.requests.length || params.redirectResponse) invalid = true;
        g.requests.push({
          url: params.request?.url,
          method: params.request?.method,
          resourceType: params.type,
          frameId: params.frameId,
          scriptInitiated: params.initiator?.type === 'script',
        });
      } else if (method === 'Network.requestWillBeSentExtraInfo')
        g.requestExtras.push(selectorFact(params.headers, selector));
      else if (method === 'Network.responseReceived')
        g.responses.push({
          status: httpStatus(params.response?.status),
          url: params.response?.url,
          headers: headerFacts(params.response?.headers),
          hasExtraInfo: params.hasExtraInfo === true,
          cached: params.response?.fromDiskCache === true || params.response?.fromServiceWorker === true,
        });
      else if (method === 'Network.responseReceivedExtraInfo')
        g.responseExtras.push({ status: httpStatus(params.statusCode), headers: headerFacts(params.headers) });
      else if (['Network.loadingFinished', 'Network.loadingFailed'].includes(method)) {
        if (g.terminal !== 'pending') invalid = true;
        g.terminal = method === 'Network.loadingFinished' ? 'finished' : 'failed';
        g.terminalEvidence = {
          state: g.terminal,
          canceled: g.terminal === 'failed' && params.canceled === true,
          errorCode:
            g.terminal === 'failed' ? (params.errorText === 'net::ERR_ABORTED' ? 'ERR_ABORTED' : 'OTHER') : null,
          responseReceivedBeforeTerminal: g.responses.length === 1,
        };
      }
      if ([g.requests, g.requestExtras, g.responses, g.responseExtras].some((entries) => entries.length > 1))
        invalid = true;
    },
    value({ mode, scope, topFrameId, naturalHeadObserved = false, documentStatus = null, headStatus = null } = {}) {
      const records = [...groups.values()].map((g) => {
        const req = g.requests[0];
        const response = g.responses[0];
        const wire = g.responseExtras[0];
        const known =
          g.requests.length === 1 &&
          g.requestExtras.length === 1 &&
          g.responses.length === 1 &&
          g.responseExtras.length === 1 &&
          response.hasExtraInfo &&
          !response.cached &&
          response.url === req.url &&
          response.status === wire.status &&
          response.headers &&
          wire.headers &&
          JSON.stringify(response.headers) === JSON.stringify(wire.headers);
        return {
          req,
          status: response?.status ?? null,
          terminal: g.terminal,
          terminalEvidence: g.terminalEvidence,
          headers: known ? wire.headers : null,
          observed: Boolean(known),
          wireSelector: g.requestExtras.length === 1 ? g.requestExtras[0] : null,
          method: req?.method,
          approvedDip: approvedDip(req?.url),
        };
      });
      const observation = (method, playwrightStatus) => {
        const candidates = records.filter(
          ({ req }) =>
            req?.url === `${new URL(target).origin}${PAYMENT_PATH}` &&
            req.method === method &&
            req.frameId === topFrameId &&
            (method === 'GET' ? req.resourceType === 'Document' : req.scriptInitiated && naturalHeadObserved),
        );
        const terminal =
          method === 'HEAD'
            ? {
                terminal: { state: 'pending', canceled: false, errorCode: null, responseReceivedBeforeTerminal: false },
              }
            : {};
        if (candidates.length !== 1) return { status: null, observed: false, headers: null, ...terminal };
        const record = candidates[0];
        const injected = mode === 'mutation' && (method === 'GET' || scope === 'same-origin');
        const selectorMatches =
          record.wireSelector &&
          record.wireSelector.present === injected &&
          (!injected || record.wireSelector.matchesSelected);
        // Chromium may abort a bodyless HEAD after exposing its complete response.
        // This is wire-header evidence, never finished transport or backend acceptance.
        const completed =
          record.terminal === 'finished' ||
          (method === 'HEAD' &&
            record.terminalEvidence.state === 'failed' &&
            record.terminalEvidence.canceled &&
            record.terminalEvidence.errorCode === 'ERR_ABORTED' &&
            record.terminalEvidence.responseReceivedBeforeTerminal);
        return {
          status: record.status,
          observed:
            !invalid &&
            record.observed &&
            completed &&
            selectorMatches &&
            record.status === playwrightStatus &&
            (method !== 'HEAD' || record.status === 200),
          headers: record.headers,
          ...(method === 'HEAD' ? { terminal: { ...record.terminalEvidence } } : {}),
        };
      };
      const collectorRecords = records.filter(({ approvedDip: approved }) => approved);
      const excludedCollectorOverrideCount = collectorRecords.filter(
        ({ wireSelector }) => wireSelector?.present === true,
      ).length;
      const selectorRequests = { observed: 0, injected: 0, stripped: 0 };
      for (const record of records)
        if (record.req && selectorRequestAllowed(record.req, target, scope)) {
          selectorRequests.observed++;
          if (record.wireSelector?.present) selectorRequests.injected++;
          else if (record.wireSelector) selectorRequests.stripped++;
        }
      const sensor = records.filter(({ req }) => {
        try {
          return (
            req?.method === 'GET' &&
            req.resourceType === 'Script' &&
            SENSOR_RE.test(new URL(req.url).pathname) &&
            new URL(req.url).origin === new URL(target).origin
          );
        } catch {
          return false;
        }
      });
      return {
        document: observation('GET', documentStatus),
        head: observation('HEAD', headStatus),
        selectorRequests,
        excludedCollectorOverrideCount,
        collectorSelectorsKnown: collectorRecords.every(({ wireSelector }) => wireSelector && !wireSelector.present),
        telemetry: aggregateDipOutcomes(records),
        sensor: {
          observed: sensor.length,
          finishedHttp2xx: sensor.filter(
            ({ terminal, status }) => terminal === 'finished' && status >= 200 && status < 300,
          ).length,
        },
        invalid,
        transportReady: records.some(
          ({ approvedDip: approved, method, terminal, status }) =>
            approved && method === 'POST' && terminal === 'finished' && status >= 200 && status < 300,
        ),
      };
    },
  };
}

const headersMatch = (observation, omitted) =>
  observation.observed === true &&
  observation.status === 200 &&
  observation.headers &&
  Object.keys(HEADER_VALUES).every(
    (name) =>
      observation.headers[name]?.present === (name !== omitted) &&
      observation.headers[name]?.matchesCanonical === (name !== omitted),
  );
const phasePassed = (phase, selector, scope) =>
  headersMatch(phase.document, phase.mode === 'mutation' ? selector : null) &&
  headersMatch(phase.head, phase.mode === 'mutation' && scope === 'same-origin' ? selector : null) &&
  phase.instrumentationPresent === true &&
  phase.paymentFieldsEmpty === true &&
  phase.sensor.finishedHttp2xx > 0 &&
  phase.telemetry.finished > 0 &&
  phase.telemetry.http2xx > 0 &&
  phase.telemetry.httpNon2xx === 0 &&
  phase.telemetry.failed === 0 &&
  phase.telemetry.statusUnknown === 0 &&
  phase.collectorSelectorsKnown === true &&
  phase.excludedCollectorOverrideCount === 0 &&
  phase.invalid === false &&
  phase.selectorRequests.observed === (scope === 'document' ? 1 : 2) &&
  phase.selectorRequests.injected === (phase.mode === 'mutation' ? (scope === 'document' ? 1 : 2) : 0) &&
  phase.selectorRequests.stripped === (phase.mode === 'control' ? (scope === 'document' ? 1 : 2) : 0);

const HEADER_ERROR_CODES = Object.freeze([
  'HEADER_CAPTURE_FAILED',
  'HEADER_EVIDENCE_FAILED',
  'HEADER_CANCELLED',
  'HEADER_EXECUTION_FAILED',
  'FETCH_INTERCEPTION_FAILED',
  'FETCH_RESUME_FAILED',
  'FETCH_DRAIN_FAILED',
  'FETCH_DISABLE_FAILED',
  'CDP_DETACH_FAILED',
  'CONTEXT_CLOSE_FAILED',
]);
const exactKeys = (object, keys) =>
  object &&
  typeof object === 'object' &&
  !Array.isArray(object) &&
  Object.keys(object).length === keys.length &&
  keys.every((key) => Object.hasOwn(object, key));
const naturalNumber = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 512;
const boolean = (value) => typeof value === 'boolean';
const validErrors = (errors) =>
  Array.isArray(errors) && errors.length <= 32 && errors.every((error) => HEADER_ERROR_CODES.includes(error));
const validHeadTerminal = (terminal) =>
  exactKeys(terminal, ['state', 'canceled', 'errorCode', 'responseReceivedBeforeTerminal']) &&
  ['pending', 'finished', 'failed'].includes(terminal.state) &&
  boolean(terminal.canceled) &&
  boolean(terminal.responseReceivedBeforeTerminal) &&
  (terminal.state === 'failed'
    ? ['ERR_ABORTED', 'OTHER'].includes(terminal.errorCode)
    : terminal.errorCode === null && !terminal.canceled) &&
  (terminal.state !== 'pending' || !terminal.responseReceivedBeforeTerminal);
const headTerminalObserved = (terminal) =>
  validHeadTerminal(terminal) &&
  terminal.responseReceivedBeforeTerminal &&
  (terminal.state === 'finished' ||
    (terminal.state === 'failed' && terminal.canceled && terminal.errorCode === 'ERR_ABORTED'));
const validObservation = (observation, head = false) =>
  exactKeys(observation, head ? ['status', 'observed', 'headers', 'terminal'] : ['status', 'observed', 'headers']) &&
  (!head ||
    (validHeadTerminal(observation.terminal) &&
      (!observation.observed ||
        (observation.status === 200 && observation.headers !== null && headTerminalObserved(observation.terminal))))) &&
  (observation.status === null || httpStatus(observation.status) !== null) &&
  boolean(observation.observed) &&
  (observation.headers === null ||
    (exactKeys(observation.headers, Object.keys(HEADER_VALUES)) &&
      Object.values(observation.headers).every(
        (bits) =>
          exactKeys(bits, ['present', 'matchesCanonical']) &&
          boolean(bits.present) &&
          boolean(bits.matchesCanonical) &&
          (bits.present || !bits.matchesCanonical),
      )));

export function validateHeaderPair(pair) {
  if (
    !exactKeys(pair, ['selector', 'scope', 'pairStartedAt', 'pairCompletedAt', 'control', 'mutation', 'result']) ||
    !Object.hasOwn(HEADER_VALUES, pair.selector) ||
    !['document', 'same-origin'].includes(pair.scope) ||
    !['passed', 'failed'].includes(pair.result)
  )
    throw new Error('HEADER_PAIR_INVALID');
  for (const mode of ['control', 'mutation']) {
    const phase = pair[mode];
    if (phase === null) {
      if (pair.result === 'passed') throw new Error('HEADER_PAIR_INVALID');
      continue;
    }
    if (
      !exactKeys(phase, [
        'mode',
        'startedAt',
        'completedAt',
        'result',
        'document',
        'head',
        'selectorRequests',
        'excludedCollectorOverrideCount',
        'collectorSelectorsKnown',
        'telemetry',
        'sensor',
        'instrumentationPresent',
        'paymentFieldsEmpty',
        'invalid',
        'errors',
        'screenshots',
        'cleanup',
      ]) ||
      phase.mode !== mode ||
      !['passed', 'failed'].includes(phase.result) ||
      !validObservation(phase.document) ||
      !validObservation(phase.head, true) ||
      !exactKeys(phase.selectorRequests, ['observed', 'injected', 'stripped']) ||
      !Object.values(phase.selectorRequests).every(naturalNumber) ||
      !naturalNumber(phase.excludedCollectorOverrideCount) ||
      !boolean(phase.collectorSelectorsKnown) ||
      !exactKeys(phase.telemetry, ['observed', 'finished', 'failed', 'http2xx', 'httpNon2xx', 'statusUnknown']) ||
      !Object.values(phase.telemetry).every(naturalNumber) ||
      phase.telemetry.http2xx + phase.telemetry.httpNon2xx + phase.telemetry.statusUnknown !==
        phase.telemetry.observed ||
      phase.telemetry.finished + phase.telemetry.failed > phase.telemetry.observed ||
      !exactKeys(phase.sensor, ['observed', 'finishedHttp2xx']) ||
      !Object.values(phase.sensor).every(naturalNumber) ||
      ![phase.instrumentationPresent, phase.paymentFieldsEmpty, phase.invalid].every(boolean) ||
      !validErrors(phase.errors) ||
      !Array.isArray(phase.screenshots) ||
      phase.screenshots.length > 6 ||
      !exactKeys(phase.cleanup, ['fetchDisabled', 'sessionDetached', 'contextClosed', 'errors']) ||
      ![phase.cleanup.fetchDisabled, phase.cleanup.sessionDetached, phase.cleanup.contextClosed].every(boolean) ||
      !validErrors(phase.cleanup.errors)
    )
      throw new Error('HEADER_PAIR_INVALID');
    if (
      phase.result === 'passed' &&
      (!phasePassed(phase, pair.selector, pair.scope) ||
        phase.errors.length ||
        phase.cleanup.errors.length ||
        !phase.cleanup.fetchDisabled ||
        !phase.cleanup.sessionDetached ||
        !phase.cleanup.contextClosed ||
        phase.screenshots.length !== 6 ||
        phase.screenshots.some((shot) => shot?.status !== 'captured'))
    )
      throw new Error('HEADER_PAIR_INVALID');
  }
  return true;
}

// Strict, tiny transport interface for run.sh. Never derive epochs from shell dispatch/completion.
export function projectHeaderPair(pair, scenarioName) {
  const selector = Object.hasOwn(HEADER_SCENARIO_SELECTORS, scenarioName)
    ? HEADER_SCENARIO_SELECTORS[scenarioName]
    : null;
  if (!selector) {
    if (pair != null) throw new Error('HEADER_PAIR_INVALID');
    return null;
  }
  validateHeaderPair(pair);
  if (
    !pair ||
    pair.selector !== selector ||
    !['document', 'same-origin'].includes(pair.scope) ||
    !['passed', 'failed'].includes(pair.result)
  )
    throw new Error('HEADER_PAIR_INVALID');
  const epoch = (iso) => {
    if (typeof iso !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(iso))
      throw new Error('HEADER_PAIR_INVALID');
    const value = Date.parse(iso);
    if (!Number.isSafeInteger(value) || value < 0 || new Date(value).toISOString() !== iso)
      throw new Error('HEADER_PAIR_INVALID');
    return value;
  };
  const pairStartedAt = epoch(pair.pairStartedAt);
  const pairCompletedAt =
    pair.pairCompletedAt === null && pair.result === 'failed' ? null : epoch(pair.pairCompletedAt);
  if (pairCompletedAt !== null && (pairCompletedAt < pairStartedAt || pairCompletedAt - pairStartedAt > 120_000))
    throw new Error('HEADER_PAIR_INVALID');
  if (
    pair.result === 'passed' &&
    (!pair.control ||
      !pair.mutation ||
      ![pair.control, pair.mutation].every(
        (phase) =>
          phase.result === 'passed' &&
          phasePassed(phase, selector, pair.scope) &&
          phase.cleanup.fetchDisabled &&
          phase.cleanup.sessionDetached &&
          phase.cleanup.contextClosed &&
          phase.cleanup.errors.length === 0,
      ))
  )
    throw new Error('HEADER_PAIR_INVALID');
  let previous = pairStartedAt;
  for (const mode of ['control', 'mutation']) {
    const phase = pair[mode];
    if (!phase) {
      if (pair.result === 'passed') throw new Error('HEADER_PAIR_INVALID');
      continue;
    }
    const started = epoch(phase.startedAt);
    const completed = phase.completedAt === null && pair.result === 'failed' ? null : epoch(phase.completedAt);
    if (
      phase.mode !== mode ||
      started < previous ||
      (completed !== null &&
        (completed < started ||
          (phase.result === 'passed' && completed - started > 40_000) ||
          (pairCompletedAt !== null && completed > pairCompletedAt)))
    )
      throw new Error('HEADER_PAIR_INVALID');
    previous = completed ?? started;
  }
  return { selector, scope: pair.scope, pairStartedAt, pairCompletedAt, result: pair.result };
}

export async function runHeaderPair({
  browser,
  target,
  selector,
  scope = 'same-origin',
  signal,
  operationTimeoutMs = 40_000,
  cleanupDeadline,
  capture,
}) {
  const base = new URL(target);
  if (
    !Object.hasOwn(HEADER_VALUES, selector) ||
    !['document', 'same-origin'].includes(scope) ||
    base.protocol !== 'https:' ||
    base.username ||
    base.password ||
    base.pathname !== '/' ||
    base.search ||
    base.hash ||
    base.hostname !== EXPECTED_HOST ||
    !Number.isFinite(operationTimeoutMs) ||
    operationTimeoutMs <= 0
  )
    throw new Error('HEADER_PAIR_INVALID');
  const pairStart = Date.now();
  const pairDeadline = pairStart + 120_000;
  const pair = {
    selector,
    scope,
    pairStartedAt: new Date(pairStart).toISOString(),
    pairCompletedAt: null,
    control: null,
    mutation: null,
    result: 'failed',
  };
  for (const mode of ['control', 'mutation']) {
    if (signal?.aborted || Date.now() >= pairDeadline) break;
    const phaseStart = Date.now();
    const phaseDeadline = Math.min(pairDeadline, phaseStart + Math.min(40_000, operationTimeoutMs));
    const execute = (operation) => {
      if (Date.now() >= phaseDeadline) return Promise.reject(new Error('OPERATION_TIMEOUT'));
      return boundedOperation(operation, phaseDeadline - Date.now(), signal);
    };
    const cleanupEnd = Math.min(phaseDeadline, cleanupDeadline?.() ?? Date.now() + DEFAULT_POLICY.cleanupMs);
    const clean = (operation) => boundedOperation(operation, Math.max(1, cleanupEnd - Date.now()));
    const phase = {
      mode,
      startedAt: new Date(phaseStart).toISOString(),
      completedAt: null,
      result: 'failed',
      document: { status: null, observed: false, headers: null },
      head: {
        status: null,
        observed: false,
        headers: null,
        terminal: { state: 'pending', canceled: false, errorCode: null, responseReceivedBeforeTerminal: false },
      },
      selectorRequests: { observed: 0, injected: 0, stripped: 0 },
      excludedCollectorOverrideCount: 0,
      collectorSelectorsKnown: false,
      telemetry: aggregateDipOutcomes([]),
      sensor: { observed: 0, finishedHttp2xx: 0 },
      instrumentationPresent: false,
      paymentFieldsEmpty: false,
      invalid: false,
      errors: [],
      screenshots: [],
      cleanup: { fetchDisabled: false, sessionDetached: false, contextClosed: false, errors: [] },
    };
    pair[mode] = phase;
    let context,
      page,
      session,
      closing = false,
      interceptionError = false,
      pausedCount = 0;
    const pending = new Map();
    const handlers = [];
    const tracker = createHeaderPairTracker(base, selector);
    let documentStatus = null,
      headStatus = null,
      topFrameId = null,
      headWindow = false,
      naturalHeadObserved = false;
    const take = async (action, cleanup = false) => {
      if (!page || !capture) {
        phase.errors.push('HEADER_CAPTURE_FAILED');
        return;
      }
      try {
        const screenshot = await (cleanup ? clean : execute)(() => capture(page, mode, action));
        phase.screenshots.push(screenshot);
        if (screenshot?.status !== 'captured') phase.errors.push('HEADER_CAPTURE_FAILED');
      } catch {
        phase.errors.push('HEADER_CAPTURE_FAILED');
      }
    };
    const listen = (event, listener) => {
      session.on(event, listener);
      handlers.push([event, listener]);
    };
    try {
      await execute(async () => {
        context = await browser.newContext({ ignoreHTTPSErrors: false });
        if (closing) await context.close();
      });
      await execute(async () => {
        page = await context.newPage();
        if (closing) await context.close();
      });
      await execute(async () => {
        session = await context.newCDPSession(page);
        if (closing) {
          await session.detach();
          await context.close();
        }
      });
      for (const event of [
        'Network.requestWillBeSent',
        'Network.requestWillBeSentExtraInfo',
        'Network.responseReceived',
        'Network.responseReceivedExtraInfo',
        'Network.loadingFinished',
        'Network.loadingFailed',
      ])
        listen(event, (params) => tracker.event(event, params));
      listen('Fetch.requestPaused', (event) => {
        pausedCount++;
        const task = (async () => {
          try {
            if (pending.has(event.requestId) || pausedCount > 512) throw new Error('PAUSE_LIMIT');
            const headers = Object.entries(event.request?.headers ?? {})
              .filter(([name]) => name.toLowerCase() !== SELECTOR_HEADER.toLowerCase())
              .map(([name, value]) => ({ name, value: String(value) }));
            if (
              !closing &&
              !signal?.aborted &&
              mode === 'mutation' &&
              selectorRequestAllowed(
                { ...event.request, resourceType: event.resourceType, redirectedRequestId: event.redirectedRequestId },
                base,
                scope,
              )
            )
              headers.push({ name: SELECTOR_HEADER, value: selector });
            await clean(() => session.send('Fetch.continueRequest', { requestId: event.requestId, headers }));
          } catch {
            interceptionError = true;
            try {
              await clean(() =>
                session.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }),
              );
            } catch {
              if (phase.cleanup.errors.length < 32) phase.cleanup.errors.push('FETCH_RESUME_FAILED');
            }
          } finally {
            pending.delete(event.requestId);
          }
        })();
        pending.set(event.requestId, task);
      });
      page.on('request', (request) => {
        if (
          headWindow &&
          request.url() === `${base.origin}${PAYMENT_PATH}` &&
          request.method() === 'HEAD' &&
          request.frame() === page.mainFrame()
        )
          naturalHeadObserved = true;
      });
      listen('Page.frameNavigated', ({ frame }) => {
        if (!frame.parentId && frame.url !== 'about:blank' && frame.url !== `${base.origin}${PAYMENT_PATH}`)
          interceptionError = true;
      });
      await execute(() => session.send('Network.enable'));
      await execute(() => session.send('Page.enable'));
      topFrameId = (await execute(() => session.send('Page.getFrameTree'))).frameTree.frame.id;
      await execute(() => session.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }));
      await take('setup');
      const response = await execute(() =>
        page.goto(`${base.origin}${PAYMENT_PATH}`, {
          waitUntil: 'domcontentloaded',
          timeout: Math.max(1, phaseDeadline - Date.now()),
        }),
      );
      documentStatus = httpStatus(response?.status());
      if (page.url() !== `${base.origin}${PAYMENT_PATH}` || response?.request().redirectedFrom())
        throw new Error('HEADER_NAVIGATION_FAILED');
      const pageState = await execute(() =>
        page.evaluate(() => {
          const names = ['cardholder_name', 'card_number', 'expiry', 'cvv', 'billing_postal_code'];
          const controls = names.map((name) => document.querySelector(`[name="${name}"]`));
          return {
            paymentFieldsEmpty: controls.every((control) => control && !control.value),
            instrumentationPresent: [...document.scripts].some((script) => script.src.includes('/__imp_apg__/js/')),
          };
        }),
      );
      phase.paymentFieldsEmpty = pageState.paymentFieldsEmpty === true;
      phase.instrumentationPresent = pageState.instrumentationPresent === true;
      await take('document');
      headWindow = true;
      const head = await execute(() =>
        page.evaluate(async (url) => {
          const response = await fetch(url, { method: 'HEAD', cache: 'no-store', redirect: 'error' });
          return { status: response.status, exactUrl: response.url === url };
        }, `${base.origin}${PAYMENT_PATH}`),
      );
      headWindow = false;
      headStatus = head?.exactUrl === true ? httpStatus(head.status) : null;
      await take('head');
      const settleDeadline = Math.min(phaseDeadline, Date.now() + 5_000);
      while (Date.now() < settleDeadline) {
        const facts = tracker.value({ mode, scope, topFrameId, naturalHeadObserved, documentStatus, headStatus });
        if (facts.transportReady && facts.sensor.finishedHttp2xx > 0 && facts.document.observed && facts.head.observed)
          break;
        await execute(
          () => new Promise((done) => setTimeout(done, Math.min(25, Math.max(1, settleDeadline - Date.now())))),
        );
      }
      const { transportReady, ...facts } = tracker.value({
        mode,
        scope,
        topFrameId,
        naturalHeadObserved,
        documentStatus,
        headStatus,
      });
      Object.assign(phase, facts);
      if (!phasePassed(phase, selector, scope) || interceptionError) phase.errors.push('HEADER_EVIDENCE_FAILED');
      await take('assertion');
    } catch {
      phase.errors.push(signal?.aborted ? 'HEADER_CANCELLED' : 'HEADER_EXECUTION_FAILED');
    } finally {
      closing = true;
      await take('cleanup', true);
      if (session) {
        try {
          await clean(() => Promise.all([...pending.values()]));
        } catch {
          phase.cleanup.errors.push('FETCH_DRAIN_FAILED');
        }
        for (const requestId of [...pending.keys()]) {
          try {
            await clean(() => session.send('Fetch.failRequest', { requestId, errorReason: 'Aborted' }));
          } catch {
            phase.cleanup.errors.push('FETCH_RESUME_FAILED');
          }
        }
        try {
          await clean(() => session.send('Fetch.disable'));
          phase.cleanup.fetchDisabled = true;
        } catch {
          phase.cleanup.errors.push('FETCH_DISABLE_FAILED');
        }
        for (const [event, handler] of handlers) {
          try {
            session.off(event, handler);
          } catch {
            phase.cleanup.errors.push('CDP_DETACH_FAILED');
          }
        }
        try {
          await clean(() => session.detach());
          phase.cleanup.sessionDetached = true;
        } catch {
          phase.cleanup.errors.push('CDP_DETACH_FAILED');
        }
      }
      await take('final', true);
      if (context) {
        try {
          await clean(() => context.close());
          phase.cleanup.contextClosed = true;
        } catch {
          phase.cleanup.errors.push('CONTEXT_CLOSE_FAILED');
        }
      }
      if (interceptionError) phase.errors.push('FETCH_INTERCEPTION_FAILED');
      phase.completedAt = new Date().toISOString();
      if (
        Date.now() <= phaseDeadline &&
        phase.errors.length === 0 &&
        phase.cleanup.errors.length === 0 &&
        phase.cleanup.fetchDisabled &&
        phase.cleanup.sessionDetached &&
        phase.cleanup.contextClosed &&
        phasePassed(phase, selector, scope)
      )
        phase.result = 'passed';
    }
    if (phase.result !== 'passed') break;
  }
  if (!signal?.aborted) pair.pairCompletedAt = new Date().toISOString();
  if (
    pair.control?.result === 'passed' &&
    pair.mutation?.result === 'passed' &&
    Date.now() <= pairDeadline &&
    !signal?.aborted
  )
    pair.result = 'passed';
  return pair;
}

export function validateTarget(rawTarget, expectedHost = EXPECTED_HOST) {
  const target = new URL(rawTarget);
  if (target.protocol !== 'https:' || target.hostname !== expectedHost || target.username || target.password)
    throw new Error(`TARGET_URL must be https://${expectedHost}`);
  return target;
}

export function sanitizeUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    for (const key of [...url.searchParams.keys()])
      if (REDACTED_URL_KEYS.has(key.toLowerCase())) url.searchParams.set(key, '[REDACTED]');
    url.hash = '';
    return url.toString();
  } catch {
    return '[invalid-url]';
  }
}

const PERSISTED_ERRORS = Object.freeze({
  screenshot: {
    code: 'SCREENSHOT_CAPTURE_FAILED',
    category: 'evidence',
    message: 'Screenshot capture failed.',
  },
  step: {
    code: 'STEP_EXECUTION_FAILED',
    category: 'scenario',
    message: 'Scenario step execution failed.',
  },
  pageCleanup: {
    code: 'PAGE_CLEANUP_FAILED',
    category: 'cleanup',
    message: 'Page cleanup failed.',
  },
  contextCleanup: {
    code: 'CONTEXT_CLEANUP_FAILED',
    category: 'cleanup',
    message: 'Browser context cleanup failed.',
  },
  browserCleanup: {
    code: 'BROWSER_CLEANUP_FAILED',
    category: 'cleanup',
    message: 'Browser cleanup failed.',
  },
});

export function persistedError(kind) {
  const failure = PERSISTED_ERRORS[kind];
  if (!failure) throw new Error('unsupported persisted error category');
  return {
    errorCode: failure.code,
    errorCategory: failure.category,
    errorMessage: failure.message,
  };
}

function reportLocalError(context) {
  console.error(`${context}: operation failed`);
}

export async function boundedOperation(operation, timeoutMs, signal) {
  if (signal?.aborted) throw new Error('RUN_INTERRUPTED');
  let timer;
  let abort;
  try {
    return await Promise.race([
      Promise.resolve().then(() => {
        if (signal?.aborted) throw new Error('RUN_INTERRUPTED');
        return operation();
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('OPERATION_TIMEOUT')), timeoutMs);
        abort = () => reject(new Error('RUN_INTERRUPTED'));
        signal?.addEventListener('abort', abort, { once: true });
      }),
    ]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

function screenshotFailureCount(scenario) {
  return (
    scenario.steps.filter((step) => step.screenshot?.status === 'failed').length +
    (scenario.finalScreenshot?.status === 'failed' ? 1 : 0)
  );
}

export function buildReceipt({ runId, target, startedAt, completedAt, scenarios, cleanup, runtime = {}, objectKey }) {
  const counts = scenarios.reduce(
    (result, scenario) => {
      result.total += 1;
      result[scenario.status] += 1;
      result.steps += scenario.steps.length;
      result.screenshotFailures += screenshotFailureCount(scenario);
      result.assertionFailures += scenario.steps.filter((step) => step.assertions?.status === 'failed').length;
      return result;
    },
    {
      total: 0,
      passed: 0,
      failed: 0,
      steps: 0,
      screenshotFailures: 0,
      assertionFailures: 0,
    },
  );
  return {
    schemaVersion: 3,
    manifest: {
      schemaVersion: SUITE_MANIFEST.schemaVersion,
      name: SUITE_MANIFEST.name,
      displayName: SUITE_MANIFEST.displayName,
      category: SUITE_MANIFEST.category,
      preconditions: SUITE_MANIFEST.preconditions,
      syntheticDataPolicy: SUITE_MANIFEST.syntheticDataPolicy,
      immediateEvidence: SUITE_MANIFEST.immediateEvidence,
      cleanup: SUITE_MANIFEST.cleanup,
      destinations: SUITE_MANIFEST.destinations,
      screenshotRequirement: SUITE_MANIFEST.screenshotRequirement,
      claimBoundary: SUITE_MANIFEST.claimBoundary,
    },
    runId,
    objectKey,
    target: { protocol: target.protocol, host: target.hostname },
    startedAt,
    completedAt,
    runtime,
    counts,
    discarded: false,
    discardReasons: [],
    scenarios,
    cleanup,
    caveat: SUITE_MANIFEST.claimBoundary,
  };
}

function networkOutcome(request) {
  const parsed = new URL(request.url());
  return {
    method: request.method(),
    resourceType: request.resourceType(),
    origin: `${parsed.protocol}//${parsed.host}`,
    path: parsed.pathname,
    terminal: 'pending',
    status: null,
    approvedDip: approvedDip(request.url()),
  };
}

export async function waitForRequestsTerminal(requests, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  const pending = () =>
    [...requests.values()].filter((request) => request.terminal === 'pending' && !request.path.includes('/socket.io/'));
  let settled = Date.now();
  let observed = requests.size;
  while (Date.now() < deadline) {
    if (pending().length || requests.size !== observed) settled = Date.now();
    observed = requests.size;
    if (!pending().length && Date.now() - settled >= Math.min(500, timeoutMs / 2)) break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return { passed: pending().length === 0, pending: pending().length };
}

function safeFilename(value) {
  return value
    .replace(/[^a-z0-9-]+/gi, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase();
}

async function maskInputs(page) {
  return page.evaluate(() => {
    const nativeValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    const nativeTextAreaSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
    const nativeSelectSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
    let cleared = 0;
    for (const control of document.querySelectorAll('input, textarea, select')) {
      if ('value' in control && control.value) cleared += 1;
      const setter =
        control instanceof HTMLInputElement
          ? nativeValueSetter
          : control instanceof HTMLTextAreaElement
            ? nativeTextAreaSetter
            : nativeSelectSetter;
      setter?.call(control, '');
      control.removeAttribute('value');
      control.removeAttribute('placeholder');
      control.setAttribute('data-csd-masked', 'true');
      control.dispatchEvent(new Event('input', { bubbles: true }));
      control.dispatchEvent(new Event('change', { bubbles: true }));
    }
    for (const node of document.querySelectorAll('[data-csd-sensitive]')) {
      node.textContent = 'Synthetic masked display';
      node.setAttribute('data-csd-masked', 'true');
    }
    return cleared;
  });
}

async function captureScreenshot(
  page,
  outputDirectory,
  runId,
  scenarioIndex,
  scenarioName,
  stepIndex,
  stepName,
  assertionStatus,
) {
  const filename = `${String(scenarioIndex + 1).padStart(2, '0')}-${safeFilename(scenarioName)}-${String(stepIndex + 1).padStart(2, '0')}-${safeFilename(stepName)}.png`;
  const scenarioDirectory = resolve(outputDirectory, safeFilename(scenarioName));
  const path = resolve(scenarioDirectory, filename);
  const temporaryPath = `${path}.tmp-${process.pid}`;
  const objectKey = `runs/${runId}/${safeFilename(scenarioName)}/${filename}`;
  const startedAt = new Date().toISOString();
  try {
    await mkdir(scenarioDirectory, { recursive: true });
    const maskedInputCount = await maskInputs(page);
    await page.screenshot({ path: temporaryPath, type: 'png', fullPage: true });
    await rename(temporaryPath, path);
    const sha256 = createHash('sha256')
      .update(await readFile(path))
      .digest('hex');
    return {
      status: 'captured',
      captureStatus: 'captured',
      assertionStatus,
      uploadStatus: 'pending',
      startedAt,
      completedAt: new Date().toISOString(),
      path: filename,
      localPath: path,
      objectKey,
      sha256,
      maskedInputCount,
    };
  } catch (error) {
    reportLocalError('screenshot capture failed', error);
    await rm(temporaryPath, { force: true }).catch(() => {});
    return {
      status: 'failed',
      captureStatus: 'failed',
      assertionStatus,
      uploadStatus: 'not-attempted',
      startedAt,
      completedAt: new Date().toISOString(),
      path: filename,
      localPath: path,
      objectKey,
      sha256: null,
      maskedInputCount: 0,
      ...persistedError('screenshot'),
    };
  }
}

function valueAt(source, field) {
  return field.split('.').reduce((value, key) => value?.[key], source);
}

function checkAssertion(actual, contract) {
  if (actual === undefined || actual === null) return false;
  if (contract.operator === 'eq') return actual === contract.value;
  if (contract.operator === 'gt') return typeof actual === 'number' && actual > contract.value;
  if (contract.operator === 'gte') return typeof actual === 'number' && actual >= contract.value;
  if (contract.operator === 'lt') return typeof actual === 'number' && actual < contract.value;
  if (contract.operator === 'oneOf') return contract.value.includes(actual);
  throw new Error(`unsupported assertion operator: ${contract.operator}`);
}

function assertEvidence(step, stepResult) {
  const contracts = step.assertions ?? [];
  if (contracts.length === 0) throw new Error(`step ${step.name} has no assertion contract`);
  const checks = contracts.map((contract) => {
    const actual = valueAt(stepResult, contract.field) ?? valueAt(stepResult.evidence, contract.field);
    return { ...contract, actual, passed: checkAssertion(actual, contract) };
  });
  return {
    status: checks.every(({ passed }) => passed) ? 'passed' : 'failed',
    checks,
  };
}

export function pageHelpers({
  terminalTimeoutMs = 8_000,
  runId = null,
  scenarioName = null,
  nativeOrigin = false,
} = {}) {
  const SCRIPT_URLS = {
    jsdelivr: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
    esm: 'https://esm.sh/moment@2.30.1',
    unpkg: 'https://unpkg.com/underscore@1.13.7/underscore-min.js',
    jspm: 'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js',
  };
  const nativeAssets = {
    'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js': '/csd-demo/static/vendor/lodash.min.js',
    'https://esm.sh/moment@2.30.1': '/csd-demo/static/vendor/moment.js',
    'https://unpkg.com/underscore@1.13.7/underscore-min.js': '/csd-demo/static/vendor/underscore-min.js',
    'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js': '/csd-demo/static/vendor/dayjs.min.js',
    'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js': '/csd-demo/static/vendor/chart.umd.min.js',
    'https://jsonplaceholder.typicode.com/favicon.ico': '/juice-shop/favicon.ico',
  };
  const nativeUrl = (url, post = false) => {
    if (!nativeOrigin) return url;
    const receiver = ['https://www.httpbin.org/post', 'https://jsonplaceholder.typicode.com/posts'].includes(url);
    const destination = nativeAssets[url] ?? (post && receiver ? '/httpbin/post' : null);
    if (!destination) throw new Error('Native endpoint mapping missing');
    return new URL(destination, location.origin).href;
  };
  const tracked = { nodes: new Set(), timers: new Set() };
  const managedContext = { runId, scenarioName };
  const CLEANUP_SETTLE_MS = 250;
  const CLEANUP_POLL_MS = 25;
  const findInput = (kind) => {
    const selectors = {
      email: ['#email', 'input[type="email"]', 'input[name*="email" i]', 'input[autocomplete="username"]'],
      password: ['#password', 'input[type="password"]', 'input[autocomplete="current-password"]'],
    };
    return selectors[kind].map((selector) => document.querySelector(selector)).find(Boolean);
  };
  const beginScenario = (runId, scenarioName) => {
    managedContext.runId = runId;
    managedContext.scenarioName = scenarioName;
    return { initialized: Boolean(runId && scenarioName) };
  };
  const terminalFetch = async (url, body) => {
    const controller = new AbortController();
    let timer;
    const request = fetch(nativeUrl(url, true), {
      method: 'POST',
      mode: 'no-cors',
      keepalive: false,
      headers: { 'content-type': 'text/plain' },
      body: JSON.stringify(body),
      signal: controller.signal,
    }).then(
      () => 'finished',
      () => (controller.signal.aborted ? 'timed-out' : 'failed'),
    );
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve('timed-out');
      }, terminalTimeoutMs);
      tracked.timers.add(timer);
    });
    try {
      return await Promise.race([request, timeout]);
    } finally {
      clearTimeout(timer);
      tracked.timers.delete(timer);
    }
  };
  const injectScript = (src, attributes = {}) =>
    new Promise((resolve) => {
      const script = document.createElement('script');
      script.src = nativeUrl(src);
      script.async = true;
      for (const [key, value] of Object.entries(attributes)) script.dataset[key] = value;
      tracked.nodes.add(script);
      const done = (terminal) => {
        clearTimeout(timer);
        tracked.timers.delete(timer);
        resolve(terminal);
      };
      script.onload = () => {
        const expectedGlobals = {
          [SCRIPT_URLS.jsdelivr]: '_',
          [SCRIPT_URLS.esm]: 'moment',
          [SCRIPT_URLS.unpkg]: '_',
          [SCRIPT_URLS.jspm]: 'dayjs',
          'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js': 'Chart',
        };
        const expected = expectedGlobals[src];
        const versions = {
          [SCRIPT_URLS.jsdelivr]: '4.17.21',
          [SCRIPT_URLS.esm]: '2.30.1',
          [SCRIPT_URLS.unpkg]: '1.13.7',
          'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js': '4.4.4',
        };
        const library = expected && window[expected];
        const nativeIdentity = versions[src]
          ? (library?.VERSION ?? library?.version) === versions[src]
          : expected === 'dayjs' &&
            typeof library === 'function' &&
            library('2026-01-02').format('YYYY-MM-DD') === '2026-01-02';
        done(typeof library === 'function' && nativeIdentity ? 'finished' : 'failed');
      };
      script.onerror = () => done('failed');
      const timer = setTimeout(() => done('timed-out'), 8_000);
      tracked.timers.add(timer);
      document.head.appendChild(script);
    });
  const isCheckable = (control) => control instanceof HTMLInputElement && ['checkbox', 'radio'].includes(control.type);
  const hasControlValue = (control) =>
    isCheckable(control)
      ? control.checked || Boolean(control.value)
      : control instanceof HTMLSelectElement
        ? [...control.options].some((option) => option.selected)
        : Boolean(control.value);
  const setNativeValue = (control, value) => {
    if (isCheckable(control)) {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set?.call(control, Boolean(value));
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(control, '');
      return;
    }
    if (control instanceof HTMLSelectElement && value === '') {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex')?.set?.call(control, -1);
      return;
    }
    const prototype =
      control instanceof HTMLInputElement
        ? HTMLInputElement.prototype
        : control instanceof HTMLTextAreaElement
          ? HTMLTextAreaElement.prototype
          : HTMLSelectElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(control, value);
  };
  const dispatchValueEvents = (control) => {
    control.dispatchEvent(new Event('input', { bubbles: true }));
    control.dispatchEvent(new Event('change', { bubbles: true }));
    control.dispatchEvent(new Event('blur', { bubbles: false }));
  };
  const syntheticFill = (control, value) => {
    if (!managedContext.runId || !managedContext.scenarioName)
      throw new Error('scenario context must be initialized before synthetic fill');
    setNativeValue(control, value);
    control.setAttribute('data-csd-synthetic', 'true');
    control.setAttribute('data-csd-run', managedContext.runId);
    control.setAttribute('data-csd-scenario', managedContext.scenarioName);
    dispatchValueEvents(control);
  };
  const managedControls = () =>
    [...document.querySelectorAll('[data-csd-synthetic="true"]')].filter(
      (control) =>
        control.getAttribute('data-csd-run') === managedContext.runId &&
        control.getAttribute('data-csd-scenario') === managedContext.scenarioName,
    );
  const setSyntheticFields = (entries) => {
    let setCount = 0;
    for (const [kind, value] of entries) {
      const control = findInput(kind);
      if (!control) continue;
      syntheticFill(control, value);
      setCount += 1;
    }
    return {
      setCount,
      markerCount: managedControls().length,
      syntheticOnly: true,
    };
  };
  const observeFields = (kinds) => ({
    observedFieldCount: kinds.filter((kind) => Boolean(findInput(kind))).length,
  });
  const observeControls = () => ({
    observedControlCount: document.querySelectorAll('input,select,textarea').length,
  });
  const injectReviewedScripts = async () => {
    const results = await Promise.all(
      Object.entries(SCRIPT_URLS).map(async ([name, url]) => [name, await injectScript(url, { csdSimulation: name })]),
    );
    return { candidateCount: results.length, ...Object.fromEntries(results) };
  };
  const counterPost = async (url, counters) => ({
    postedCount: Object.values(counters).reduce((sum, value) => sum + Number(value || 0), 0),
    terminal: await terminalFetch(url, counters),
  });
  const attemptChannels = async () => {
    const fetchPost = await terminalFetch('https://www.httpbin.org/post', {
      observedFieldCount: 2,
    });
    const image = new Image();
    image.alt = 'synthetic evidence';
    image.src = nativeUrl('https://jsonplaceholder.typicode.com/favicon.ico');
    tracked.nodes.add(image);
    document.body.appendChild(image);
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = nativeUrl(SCRIPT_URLS.jsdelivr);
    tracked.nodes.add(link);
    document.head.appendChild(link);
    return {
      channelCount: 3,
      fetchPost,
      imageAttempted: true,
      prefetchAttempted: true,
    };
  };
  const installBanner = () => {
    const banner = document.createElement('div');
    banner.dataset.csdOverlay = 'banner';
    banner.textContent = 'Synthetic CSD simulation';
    banner.style.cssText =
      'position:fixed;inset:20% 20% auto;z-index:2147483647;background:#fff;border:4px solid #c00;padding:2rem';
    tracked.nodes.add(banner);
    document.body.appendChild(banner);
    return { installed: true };
  };
  const sensitiveValueCount = () => {
    const syntheticValue = /synthetic|password|(?:\d[ -]?){12,19}/i;
    const controlValues = [...document.querySelectorAll('input,textarea,select')].map((control) => control.value);
    const sensitiveText = [...document.querySelectorAll('[data-csd-sensitive]')].map((node) => node.textContent);
    return [...controlValues, ...sensitiveText].filter((value) => value && syntheticValue.test(value)).length;
  };
  const cleanupPage = async () => {
    for (const node of tracked.nodes) node.remove();
    tracked.nodes.clear();
    for (const timer of tracked.timers) clearTimeout(timer);
    tracked.timers.clear();
    if (window.__csdKeyListener) document.removeEventListener('keydown', window.__csdKeyListener);
    window.__csdKeyListener = null;
    const deadline = Date.now() + CLEANUP_SETTLE_MS;
    let controls = managedControls();
    do {
      for (const control of controls) {
        setNativeValue(control, '');
        if (!isCheckable(control)) control.removeAttribute('value');
        control.removeAttribute('placeholder');
        dispatchValueEvents(control);
      }
      await new Promise((resolve) => setTimeout(resolve, CLEANUP_POLL_MS));
      controls = managedControls();
    } while (controls.some(hasControlValue) && Date.now() < deadline);
    const managedControlValueCount = controls.filter(hasControlValue).length;
    if (managedControlValueCount === 0)
      for (const control of controls) {
        control.removeAttribute('data-csd-synthetic');
        control.removeAttribute('data-csd-run');
        control.removeAttribute('data-csd-scenario');
      }
    for (const node of document.querySelectorAll('[data-csd-sensitive]')) node.textContent = '';
    return {
      artifactCount: document.querySelectorAll(
        '[data-csd-overlay],[data-csd-simulation],[data-tag-manager="synthetic"],link[rel="prefetch"]',
      ).length,
      managedControlValueCount,
      sensitiveValueCount: sensitiveValueCount(),
      timerCount: tracked.timers.size,
      listenerAttached: Boolean(window.__csdKeyListener),
    };
  };
  window.__csdSim = {
    beginScenario,
    observeFields,
    observeControls,
    setSyntheticLogin: () =>
      setSyntheticFields([
        ['email', 'synthetic-login@example.com'],
        ['password', 'Synthetic-Only-Password-42!'],
      ]),
    setSyntheticRegistration: () => {
      const controls = [...document.querySelectorAll('input,textarea,select')].slice(0, 8);
      let setCount = 0;
      for (const [index, control] of controls.entries()) {
        if (control instanceof HTMLSelectElement) continue;
        syntheticFill(
          control,
          isCheckable(control)
            ? false
            : control.type === 'password'
              ? 'Synthetic-Only-Password-42!'
              : `synthetic-${index}@example.com`,
        );
        setCount += 1;
      }
      return {
        setCount,
        markerCount: document.querySelectorAll('[data-csd-synthetic="true"]').length,
        syntheticOnly: true,
      };
    },
    counterPost,
    injectReviewedScripts,
    attemptChannels,
    installBanner,
    cleanupPage,
    installPaymentOverlay() {
      const originalFieldCount = document.querySelectorAll('input,select,textarea').length;
      const overlay = document.createElement('div');
      overlay.dataset.csdOverlay = 'payment';
      overlay.style.cssText =
        'position:fixed;inset:15%;z-index:2147483647;background:#fff;border:4px solid #c00;padding:2rem';
      const label = document.createElement('div');
      label.dataset.csdSensitive = 'payment';
      label.textContent = 'Synthetic card •••• •••• •••• ••••';
      overlay.appendChild(label);
      tracked.nodes.add(overlay);
      document.body.appendChild(overlay);
      window.__csdOriginalPaymentFieldCount = originalFieldCount;
      return {
        installed: true,
        maskedDisplayOnly: !overlay.querySelector('input'),
        originalFieldCount,
      };
    },
    async postOriginalPaymentFieldCounter() {
      const originalFieldCount = window.__csdOriginalPaymentFieldCount;
      return counterPost('https://www.httpbin.org/post', {
        originalFieldCount,
      });
    },
    async injectObfuscatedLoader() {
      const encoded = 'aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS9sb2Rhc2hANC4xNy4yMS9sb2Rhc2gubWluLmpz';
      const decoded = atob(encoded);
      return {
        decodedBytes: decoded.length,
        terminal: await injectScript(decoded, {
          csdSimulation: 'obfuscated-loader',
        }),
      };
    },
    async installTagManagerCandidate() {
      const terminal = await injectScript('https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js', {
        tagManager: 'synthetic',
      });
      return { tagged: true, terminal };
    },
    async highVolumeAttempts() {
      const scriptAttempts = [
        ['scriptJsdelivr', SCRIPT_URLS.jsdelivr],
        ['scriptEsm', SCRIPT_URLS.esm],
        ['scriptUnpkg', SCRIPT_URLS.unpkg],
        ['scriptJspm', SCRIPT_URLS.jspm],
        ['scriptChartjs', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js'],
      ];
      const outcomes = Object.fromEntries(
        await Promise.all(
          scriptAttempts.map(async ([name, url]) => [name, await injectScript(url, { csdSimulation: 'high-volume' })]),
        ),
      );
      outcomes.postHttpbin = await terminalFetch('https://www.httpbin.org/post', { count: 1 });
      outcomes.postJsonplaceholder = await terminalFetch('https://jsonplaceholder.typicode.com/posts', { count: 1 });
      return {
        attemptCount: 7,
        scriptCount: 5,
        postCount: 2,
        terminalCount: Object.values(outcomes).filter((value) =>
          ['finished', 'blocked', 'failed', 'timed-out'].includes(value),
        ).length,
        outcomes,
      };
    },
    installFormOverlay() {
      const originalFieldCount = document.querySelectorAll('input,select,textarea').length;
      const overlay = document.createElement('form');
      overlay.dataset.csdOverlay = 'login';
      overlay.style.cssText =
        'position:fixed;inset:20%;z-index:2147483647;background:#fff;border:4px solid #c00;padding:2rem';
      overlay.textContent = 'Synthetic login overlay (no values collected)';
      tracked.nodes.add(overlay);
      document.body.appendChild(overlay);
      return {
        originalFieldCount,
        installed: true,
        hasGeometry: overlay.getBoundingClientRect().width > 0,
      };
    },
    async runKeyCounter(count) {
      let eventCount = 0;
      const listener = () => {
        eventCount += 1;
      };
      window.__csdKeyListener = listener;
      document.addEventListener('keydown', listener);
      for (let index = 0; index < count; index += 1)
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'x', bubbles: true }));
      document.removeEventListener('keydown', listener);
      window.__csdKeyListener = null;
      const timer = setTimeout(() => {}, 1);
      clearTimeout(timer);
      return { eventCount, listenerDetached: true, timerCleared: true };
    },
  };
}

export async function validateAwsRuntime(environment = process.env, platform = process.platform) {
  if (environment.CSD_AWS_RUNTIME !== '1') throw new Error('CSD_AWS_RUNTIME=1 is required for real browser execution');
  if (platform !== 'linux') throw new Error(`AWS browser execution requires Linux; detected ${platform}`);
  const sourceCommit = environment.SOURCE_COMMIT;
  if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? '')) throw new Error('SOURCE_COMMIT must be the exact deployed commit');
  const statusPath = environment.CSD_AWS_STATUS_PATH ?? '/opt/traffic-generator/status.json';
  const status = JSON.parse(await readFile(statusPath, 'utf8'));
  const allowedStatuses = environment.CSD_AWS_ALLOW_VERIFYING_STATUS === '1' ? ['verifying'] : ['ready'];
  if (!allowedStatuses.includes(status.status) || status.source_commit !== sourceCommit || status.runtime !== 'aws')
    throw new Error('AWS deployment status is not ready or does not match SOURCE_COMMIT');
  const chromePath = environment.CHROME_PATH ?? '/opt/chrome/chrome';
  if (chromePath !== '/opt/chrome/chrome') throw new Error('CHROME_PATH must be /opt/chrome/chrome');
  const playwrightRoot = environment.CSD_PLAYWRIGHT_ROOT ?? '/opt/traffic-generator/node_modules';
  if (playwrightRoot !== '/opt/traffic-generator/node_modules')
    throw new Error('CSD_PLAYWRIGHT_ROOT must be /opt/traffic-generator/node_modules');
  const playwrightPath = resolve(playwrightRoot, 'playwright-core/package.json');
  await access(chromePath, constants.X_OK);
  await access(playwrightPath, constants.R_OK);
  if (!/^:\d+$/.test(environment.DISPLAY ?? '')) throw new Error('DISPLAY must identify the deployed Xvfb display');
  const displaySocket = `/tmp/.X11-unix/X${environment.DISPLAY.slice(1)}`;
  const socket = await stat(displaySocket);
  if (!socket.isSocket()) throw new Error(`Xvfb display socket is unavailable: ${displaySocket}`);
  const runId = environment.RUN_ID ?? '';
  if (!/^[a-z0-9][a-z0-9-]{0,127}$/.test(runId))
    throw new Error('RUN_ID must contain only lowercase letters, digits, and hyphens');
  const outputDirectory = resolve(environment.CSD_AWS_OUTPUT_DIR ?? '');
  const expectedOutputDirectory = resolve('/opt/traffic-generator/runtime/results', runId);
  if (outputDirectory !== expectedOutputDirectory)
    throw new Error(`CSD_AWS_OUTPUT_DIR must equal ${expectedOutputDirectory}`);
  const runtime = {
    repository: environment.SOURCE_REPOSITORY_URL,
    sourceCommit,
    chromeVersion: environment.CHROME_VERSION ?? status.chrome_version,
    nodeVersion: environment.NODE_VERSION ?? status.node_version,
    amiId: environment.AMI_ID,
    instanceId: environment.INSTANCE_ID ?? status.instance_id,
    region: environment.AWS_REGION,
    manifestVersion: environment.DEPLOYMENT_MANIFEST_VERSION,
    manifestDigest: environment.DEPLOYMENT_MANIFEST_SHA256,
  };
  for (const [field, value] of Object.entries(runtime))
    if (!value) throw new Error(`runtime provenance is missing ${field}`);
  if (
    status.repository !== runtime.repository ||
    status.source_commit !== runtime.sourceCommit ||
    status.ami_id !== runtime.amiId ||
    status.region !== runtime.region ||
    status.manifest?.version !== runtime.manifestVersion ||
    status.manifest?.sha256 !== runtime.manifestDigest
  )
    throw new Error('AWS deployment status provenance does not match the deployed runtime environment');
  return {
    chromePath,
    outputDirectory,
    playwrightPath,
    runId,
    sourceCommit,
    statusPath,
    runtime,
  };
}

export async function runSuite(options = {}) {
  const signal = options.signal;
  const cleanupDeadline = () =>
    Math.max(1, (options.cleanupDeadline?.() ?? Date.now() + DEFAULT_POLICY.cleanupMs) - Date.now());
  const cleanupOperation = (operation) => boundedOperation(operation, cleanupDeadline());
  const execute = (operation) => boundedOperation(operation, options.operationTimeoutMs ?? 40_000, signal);
  const captureWithinDeadline = async (operation) => {
    try {
      return await cleanupOperation(operation);
    } catch {
      return { status: 'failed', captureStatus: 'failed', ...persistedError('screenshot') };
    }
  };
  let runtime;
  if (!options.playwright) runtime = await validateAwsRuntime();
  const expectedHost = options.expectedHost ?? EXPECTED_HOST;
  const target = validateTarget(options.targetUrl ?? process.env.TARGET_URL ?? `https://${expectedHost}`, expectedHost);
  const outputDirectory = resolve(
    options.outputDirectory ??
      runtime?.outputDirectory ??
      process.env.RESULTS_DIR ??
      `results/${Date.now()}-csd-violations`,
  );
  const runId = options.runId ?? runtime?.runId ?? process.env.RUN_ID ?? `csd-${Date.now()}-${process.pid}`;
  if (!/^[a-z0-9][a-z0-9-]{0,127}$/.test(runId)) throw new Error('runId contains unsafe path characters');
  const requestedScenario = options.scenario ?? process.env.CSD_SCENARIO;
  const selectedScenarios = requestedScenario ? SCENARIOS.filter(({ name }) => name === requestedScenario) : SCENARIOS;
  if (requestedScenario && selectedScenarios.length !== 1) throw new Error('CSD_SCENARIO is not allowlisted');
  const executablePath = options.executablePath ?? runtime?.chromePath ?? process.env.CHROME_PATH;
  const startedAt = new Date().toISOString();
  await mkdir(outputDirectory, { recursive: true });
  let playwright = options.playwright;
  if (!playwright) {
    const packagePath = runtime.playwrightPath;
    playwright = await import(pathToFileURL(resolve(dirname(packagePath), 'index.mjs')).href);
  }
  const browser = await playwright.chromium.launch({
    executablePath,
    channel: executablePath ? undefined : 'chrome',
    headless: options.headless ?? false,
    args: options.browserArgs ?? ['--disable-dev-shm-usage'],
  });
  const scenarioResults = [];
  const cleanup = { browser: 'pending', contexts: 0, errors: [] };
  try {
    for (const [scenarioIndex, scenario] of selectedScenarios.entries()) {
      if (signal?.aborted) break;
      if (scenario.kind === 'header-pair') {
        const step = scenario.steps[0];
        const headerPair = await runHeaderPair({
          browser,
          target: new URL(target.origin),
          selector: step.selector,
          scope: step.scope,
          signal,
          operationTimeoutMs: options.operationTimeoutMs,
          cleanupDeadline: options.cleanupDeadline,
          capture: (page, mode, action) =>
            captureScreenshot(
              page,
              outputDirectory,
              runId,
              scenarioIndex,
              scenario.name,
              mode === 'control' ? 0 : 1,
              `${mode}-${action}`,
              'not-run',
            ),
        });
        projectHeaderPair(headerPair, scenario.name);
        cleanup.contexts += [headerPair.control, headerPair.mutation].filter(Boolean).length;
        const phases = [headerPair.control, headerPair.mutation].filter(Boolean);
        const lastShot = phases.at(-1)?.screenshots.at(-1) ?? { status: 'failed' };
        scenarioResults.push({
          ...scenario,
          status: headerPair.result,
          startedAt: headerPair.pairStartedAt,
          completedAt: headerPair.pairCompletedAt,
          network: [],
          instrumentation: {},
          steps: [
            {
              name: step.name,
              operation: step.op,
              startedAt: headerPair.pairStartedAt,
              completedAt: headerPair.pairCompletedAt,
              status: headerPair.result,
              evidence: { headerPair },
              assertions: { status: headerPair.result },
              screenshot: lastShot,
            },
          ],
          finalScreenshot: lastShot,
        });
        continue;
      }
      const context = await execute(() =>
        browser.newContext({
          ignoreHTTPSErrors: options.ignoreHTTPSErrors ?? false,
          extraHTTPHeaders: browserRequests.childHeaders(),
        }),
      );
      cleanup.contexts += 1;
      if (options.routeSetup) await options.routeSetup(context, target);
      await context.addInitScript(pageHelpers, {
        runId,
        scenarioName: scenario.name,
        nativeOrigin: options.runtime?.platform === 'azure',
      });
      const page = await execute(() => context.newPage());
      const requests = new Map();
      const instrumentation = { sensorRequests: 0, dipRequests: 0 };
      const scenarioResult = {
        name: scenario.name,
        displayName: scenario.displayName,
        category: scenario.category,
        preconditions: scenario.preconditions,
        syntheticDataPolicy: scenario.syntheticDataPolicy,
        immediateEvidence: scenario.immediateEvidence,
        cleanupRequirement: scenario.cleanup,
        destinations: scenario.destinations,
        screenshotRequirement: scenario.screenshotRequirement,
        claimBoundary: scenario.claimBoundary,
        status: 'passed',
        startedAt: new Date().toISOString(),
        steps: [],
        network: [],
        instrumentation,
      };
      page.on('request', (request) => {
        const outcome = networkOutcome(request);
        requests.set(request, outcome);
        if (SENSOR_RE.test(request.url())) instrumentation.sensorRequests += 1;
        if (DIP_RE.test(request.url()) || approvedDip(request.url())) instrumentation.dipRequests += 1;
      });
      page.on('response', (response) => {
        const outcome = requests.get(response.request());
        if (outcome && (approvedDip(response.url()) || SENSOR_RE.test(response.url())))
          outcome.status = httpStatus(response.status());
      });
      page.on('requestfinished', (request) => {
        const outcome = requests.get(request);
        if (outcome) outcome.terminal = 'finished';
      });
      page.on('requestfailed', (request) => {
        const outcome = requests.get(request);
        if (outcome) outcome.terminal = 'blocked';
      });
      try {
        for (const [stepIndex, step] of scenario.steps.entries()) {
          if (signal?.aborted) {
            scenarioResult.status = 'failed';
            break;
          }
          const stepResult = {
            name: step.name,
            operation: step.op,
            startedAt: new Date().toISOString(),
            status: 'passed',
          };
          try {
            if (step.op === 'navigate') {
              const route = options.routePrefix ? options.routePrefix.replace(/\/$/, '') + step.route : step.route;
              const stepUrl = new URL(route, target);
              if (stepUrl.hostname !== target.hostname)
                throw new Error('scenario navigation escaped the validated target');
              const response = await execute(() =>
                page.goto(stepUrl.toString(), {
                  waitUntil: 'domcontentloaded',
                  timeout: 40_000,
                }),
              );
              stepResult.navigationStatus = response?.status() ?? null;
              for (const selector of step.waitFor ?? [])
                await execute(() =>
                  page.waitForSelector(selector, {
                    state: 'attached',
                    timeout: step.waitTimeoutMs ?? 15_000,
                  }),
                );
            } else if (step.op === 'evaluate' || step.op === 'cleanup') {
              if (step.op === 'cleanup' && options.drainRequests) {
                stepResult.preCleanupDrain = await execute(() => waitForRequestsTerminal(requests));
                if (!stepResult.preCleanupDrain.passed) throw new Error('Application requests remain before cleanup');
              }
              const evidence = await execute(() => page.evaluate(step.run));
              if (!evidence || typeof evidence !== 'object') throw new Error(`${step.op} step returned no evidence`);
              stepResult.evidence = evidence;
            } else throw new Error(`unsupported operation: ${step.op}`);
            stepResult.assertions = assertEvidence(step, stepResult);
            if (stepResult.assertions.status === 'failed') throw new Error('assertion contract failed');
          } catch (error) {
            reportLocalError(`step ${scenario.name}/${step.name} failed`, error);
            stepResult.status = 'failed';
            Object.assign(stepResult, persistedError('step'));
            scenarioResult.status = 'failed';
          }
          stepResult.completedAt = new Date().toISOString();
          stepResult.screenshot = await captureWithinDeadline(() =>
            captureScreenshot(
              page,
              outputDirectory,
              runId,
              scenarioIndex,
              scenario.name,
              stepIndex,
              step.name,
              stepResult.assertions?.status ?? 'not-run',
            ),
          );
          if (stepResult.screenshot.status === 'failed') scenarioResult.status = 'failed';
          scenarioResult.steps.push(stepResult);
        }
      } finally {
        try {
          if (options.drainRequests) {
            scenarioResult.preFinalCleanupDrain = await cleanupOperation(() => waitForRequestsTerminal(requests));
            if (!scenarioResult.preFinalCleanupDrain.passed) scenarioResult.status = 'failed';
          }
          await cleanupOperation(() => page.evaluate(() => window.__csdSim?.cleanupPage()));
        } catch (error) {
          reportLocalError(`page cleanup ${scenario.name} failed`, error);
          cleanup.errors.push({
            scenario: scenario.name,
            ...persistedError('pageCleanup'),
          });
          scenarioResult.status = 'failed';
        }
        if (options.drainRequests) {
          scenarioResult.networkDrain = await cleanupOperation(() => waitForRequestsTerminal(requests));
          if (!scenarioResult.networkDrain.passed) scenarioResult.status = 'failed';
        }
        scenarioResult.finalScreenshot = await captureWithinDeadline(() =>
          captureScreenshot(
            page,
            outputDirectory,
            runId,
            scenarioIndex,
            scenario.name,
            scenario.steps.length,
            'final',
            scenarioResult.status === 'passed' ? 'passed' : 'failed',
          ),
        );
        if (scenarioResult.finalScreenshot.status === 'failed') scenarioResult.status = 'failed';
        scenarioResult.network = [...requests.values()];
        scenarioResult.instrumentation.dipOutcomes = aggregateDipOutcomes(scenarioResult.network);
        scenarioResult.completedAt = new Date().toISOString();
        try {
          if (options.routeCleanup) await cleanupOperation(() => options.routeCleanup(context));
          if (options.drainRequests) {
            scenarioResult.finalNetworkDrain = await cleanupOperation(() => waitForRequestsTerminal(requests));
            if (!scenarioResult.finalNetworkDrain.passed) scenarioResult.status = 'failed';
          }
          await cleanupOperation(() => context.close());
        } catch (error) {
          reportLocalError(`context cleanup ${scenario.name} failed`, error);
          cleanup.errors.push({
            scenario: scenario.name,
            ...persistedError('contextCleanup'),
          });
          scenarioResult.status = 'failed';
        }
        scenarioResults.push(scenarioResult);
      }
    }
  } catch {
    reportLocalError('scenario setup failed');
    cleanup.errors.push(persistedError('step'));
  } finally {
    try {
      await cleanupOperation(() => browser.close());
      cleanup.browser = 'closed';
    } catch (error) {
      reportLocalError('browser cleanup failed', error);
      cleanup.browser = 'failed';
      cleanup.errors.push(persistedError('browserCleanup'));
    }
  }
  const receiptDirectory =
    selectedScenarios.length === 1
      ? resolve(outputDirectory, safeFilename(selectedScenarios[0].name))
      : outputDirectory;
  const receiptObjectKey =
    selectedScenarios.length === 1
      ? `runs/${runId}/${safeFilename(selectedScenarios[0].name)}/receipt.json`
      : `runs/${runId}/receipt.json`;
  const receipt = buildReceipt({
    runId,
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    scenarios: scenarioResults,
    cleanup,
    runtime: options.runtime ?? runtime?.runtime ?? {},
    objectKey: receiptObjectKey,
  });
  await mkdir(receiptDirectory, { recursive: true });
  const receiptPath = resolve(receiptDirectory, 'receipt.json');
  const temporaryPath = `${receiptPath}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporaryPath, receiptPath);
  return {
    receipt,
    receiptPath,
    exitCode: signal?.aborted
      ? 143
      : receipt.counts.failed === 0 &&
          scenarioResults.length === selectedScenarios.length &&
          cleanup.errors.length === 0
        ? 0
        : 1,
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  const controller = new AbortController();
  let cancellationDeadline;
  const cancel = () => {
    cancellationDeadline ??= Date.now() + DEFAULT_POLICY.cleanupMs;
    controller.abort();
  };
  process.on('SIGTERM', cancel);
  process.on('SIGINT', cancel);
  try {
    const result = await runSuite({
      signal: controller.signal,
      cleanupDeadline: () => cancellationDeadline ?? Date.now() + DEFAULT_POLICY.cleanupMs,
    });
    console.log(JSON.stringify({ runId: result.receipt.runId, counts: result.receipt.counts }));
    process.exitCode = result.exitCode;
  } catch {
    console.error('ERROR: runner prerequisite failed');
    process.exitCode = controller.signal.aborted ? 143 : 78;
  } finally {
    process.removeListener('SIGTERM', cancel);
    process.removeListener('SIGINT', cancel);
  }
}

export { EXPECTED_HOST };
