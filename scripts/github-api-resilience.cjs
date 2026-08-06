#!/usr/bin/env node
'use strict';

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_WAIT_BUDGET_SECONDS = 900;
const DEFAULT_SECONDARY_BACKOFF_SECONDS = 60;
const DEFAULT_SECONDARY_MAX_SECONDS = 600;
const DEFAULT_TRANSIENT_BACKOFF_SECONDS = 5;
const DEFAULT_TRANSIENT_MAX_SECONDS = 60;
const PRIMARY_RESET_GRACE_SECONDS = 5;

class GitHubRetryDeferredError extends Error {
  constructor(message, options = {}) {
    super(message, { cause: options.cause });
    this.name = 'GitHubRetryDeferredError';
    this.code = 84;
    this.kind = options.kind;
    this.operationName = options.operationName;
    this.waitSeconds = options.waitSeconds;
    this.attempt = options.attempt;
    this.maxAttempts = options.maxAttempts;
  }
}

function headersFrom(error) {
  const source = error?.response?.headers ?? error?.headers ?? {};
  if (typeof source.get === 'function') {
    return new Proxy(
      {},
      {
        get: (_target, name) => source.get(String(name)) ?? source.get(String(name).toLowerCase()),
      },
    );
  }
  return Object.fromEntries(Object.entries(source).map(([name, value]) => [name.toLowerCase(), value]));
}

function headerValue(headers, name) {
  const value = headers[name.toLowerCase()] ?? headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function integer(value) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function retryAfterSeconds(value, nowSeconds = Date.now() / 1000) {
  const numeric = integer(value);
  if (numeric !== undefined && /^\s*\d+\s*$/.test(String(value))) {
    return Math.max(0, numeric);
  }
  const timestamp = Date.parse(String(value ?? ''));
  if (!Number.isNaN(timestamp)) {
    return Math.max(0, Math.ceil(timestamp / 1000 - nowSeconds));
  }
  return undefined;
}

function classifyGitHubError(error, options = {}) {
  const status = Number(error?.status ?? error?.response?.status ?? 0);
  const headers = headersFrom(error);
  const message = [error?.message, error?.response?.data?.message, error?.response?.data?.documentation_url]
    .filter(Boolean)
    .join(' ');
  const lower = message.toLowerCase();
  const remaining = integer(headerValue(headers, 'x-ratelimit-remaining'));
  const resetAtSeconds = integer(headerValue(headers, 'x-ratelimit-reset'));
  const retryAfter = retryAfterSeconds(headerValue(headers, 'retry-after'), options.nowSeconds);
  const secondaryMessage =
    /secondary rate|abuse detection|submitted too quickly|temporarily blocked from content creation|content creation.*blocked/.test(
      lower,
    );

  if (retryAfter !== undefined || secondaryMessage || (status === 429 && remaining !== 0)) {
    return {
      kind: 'secondary',
      retryable: true,
      status,
      retryAfterSeconds: retryAfter,
      remaining,
      resetAtSeconds,
    };
  }
  if (remaining === 0 || /api rate limit exceeded|primary rate limit/.test(lower)) {
    return {
      kind: 'primary',
      retryable: true,
      status,
      remaining,
      resetAtSeconds,
    };
  }
  if (
    [408, 429, 500, 502, 503, 504].includes(status) ||
    ['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENETUNREACH'].includes(error?.code)
  ) {
    return { kind: 'transient', retryable: true, status, remaining, resetAtSeconds };
  }
  return { kind: 'fatal', retryable: false, status, remaining, resetAtSeconds };
}

function computeWaitSeconds(classification, options = {}) {
  const attempt = Math.max(1, Number(options.attempt ?? 1));
  const nowSeconds = Number(options.nowSeconds ?? Date.now() / 1000);
  const jitterSeconds = Math.max(0, Number(options.jitterSeconds ?? 3));
  const random = options.random ?? Math.random;
  let waitSeconds;

  if (classification.kind === 'primary') {
    if (!Number.isFinite(classification.resetAtSeconds)) {
      waitSeconds = DEFAULT_SECONDARY_BACKOFF_SECONDS;
    } else {
      waitSeconds = Math.max(1, Math.ceil(classification.resetAtSeconds - nowSeconds) + PRIMARY_RESET_GRACE_SECONDS);
    }
  } else if (classification.kind === 'secondary') {
    const maximum = Number(options.maxBackoffSeconds ?? DEFAULT_SECONDARY_MAX_SECONDS);
    waitSeconds =
      classification.retryAfterSeconds ?? Math.min(maximum, DEFAULT_SECONDARY_BACKOFF_SECONDS * 2 ** (attempt - 1));
  } else {
    const maximum = Number(options.maxTransientBackoffSeconds ?? DEFAULT_TRANSIENT_MAX_SECONDS);
    waitSeconds = Math.min(maximum, DEFAULT_TRANSIENT_BACKOFF_SECONDS * 2 ** (attempt - 1));
  }

  const jitter = jitterSeconds > 0 ? Math.floor(random() * (jitterSeconds + 1)) : 0;
  return Math.max(0, Math.ceil(waitSeconds + jitter));
}

function formatRetryProgress(event) {
  return (
    `[WAIT] ${event.operationName}: ${event.kind} GitHub limit on attempt ` +
    `${event.attempt}/${event.maxAttempts}; waiting ${event.waitSeconds}s; ` +
    `next attempt ${event.nextAttemptAt}`
  );
}

async function readPrimaryRateLimit({ request, resource = 'core' } = {}) {
  if (typeof request !== 'function') {
    throw new TypeError('readPrimaryRateLimit requires a GitHub request function');
  }
  const response = await request('GET /rate_limit');
  const rate = response?.data?.resources?.[resource] ?? response?.data?.rate;
  if (!rate) throw new Error(`GitHub /rate_limit omitted the ${resource} resource`);
  return {
    limit: Number(rate.limit),
    remaining: Number(rate.remaining),
    resetAtSeconds: Number(rate.reset),
    resource,
  };
}

function sleep(seconds) {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

async function retryGitHub(operation, options = {}) {
  if (typeof operation !== 'function') throw new TypeError('retryGitHub requires an operation');
  const operationName = options.operationName ?? 'GitHub API operation';
  const maxAttempts = Math.max(1, Number(options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS));
  const totalWaitBudgetSeconds = Math.max(0, Number(options.totalWaitBudgetSeconds ?? DEFAULT_WAIT_BUDGET_SECONDS));
  const nowSeconds = options.nowSeconds ?? (() => Date.now() / 1000);
  const sleepSeconds = options.sleepSeconds ?? sleep;
  const onProgress = options.onProgress ?? ((event) => console.log(formatRetryProgress(event)));
  let totalWaitSeconds = 0;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await operation({ attempt, maxAttempts });
    } catch (error) {
      let classification = classifyGitHubError(error, { nowSeconds: nowSeconds() });
      if (!classification.retryable) throw error;

      if (
        classification.kind === 'primary' &&
        !Number.isFinite(classification.resetAtSeconds) &&
        typeof options.readPrimaryRateLimit === 'function'
      ) {
        const rate = await options.readPrimaryRateLimit();
        classification = { ...classification, resetAtSeconds: rate.resetAtSeconds };
      }

      const waitSeconds = computeWaitSeconds(classification, {
        attempt,
        nowSeconds: nowSeconds(),
        jitterSeconds: options.jitterSeconds,
        maxBackoffSeconds: options.maxBackoffSeconds,
        maxTransientBackoffSeconds: options.maxTransientBackoffSeconds,
        random: options.random,
      });
      const exhausted = attempt >= maxAttempts || totalWaitSeconds + waitSeconds > totalWaitBudgetSeconds;
      if (exhausted) {
        throw new GitHubRetryDeferredError(
          `${operationName} deferred after ${attempt}/${maxAttempts} attempts; ` +
            `${classification.kind} cooldown requires ${waitSeconds}s`,
          {
            cause: error,
            kind: classification.kind,
            operationName,
            waitSeconds,
            attempt,
            maxAttempts,
          },
        );
      }

      const nextAttemptAt = new Date((nowSeconds() + waitSeconds) * 1000).toISOString();
      const event = {
        operationName,
        kind: classification.kind,
        attempt,
        maxAttempts,
        waitSeconds,
        nextAttemptAt,
        totalWaitSeconds: totalWaitSeconds + waitSeconds,
      };
      onProgress(event);
      await sleepSeconds(waitSeconds);
      totalWaitSeconds += waitSeconds;
    }
  }
  throw new Error(`${operationName} reached an unreachable retry state`);
}

async function requestGitHubApi(endpoint, options = {}) {
  const token = options.token;
  const fetchImplementation = options.fetch ?? globalThis.fetch;
  if (!token) throw new Error('GitHub API token is required');
  if (typeof fetchImplementation !== 'function') throw new Error('fetch is unavailable');
  const startUrl = endpoint.startsWith('https://') ? endpoint : `https://api.github.com/${endpoint.replace(/^\//, '')}`;
  const requestPage = async (url) => {
    const response = await fetchImplementation(url, {
      method: options.method ?? 'GET',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'f5-sales-demo-governance',
        'x-github-api-version': '2022-11-28',
        ...options.headers,
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const raw = await response.text();
    let data;
    try {
      data = raw ? JSON.parse(raw) : null;
    } catch {
      data = raw;
    }
    if (!response.ok) {
      const error = new Error(data?.message ?? `GitHub API returned HTTP ${response.status}`);
      error.status = response.status;
      error.response = { status: response.status, headers: response.headers, data };
      throw error;
    }
    return { data, link: response.headers.get('link') };
  };
  const rateLimit = () =>
    readPrimaryRateLimit({
      request: async (route) => {
        if (route !== 'GET /rate_limit') throw new Error(`unexpected rate route: ${route}`);
        const response = await requestPage('https://api.github.com/rate_limit');
        return { data: response.data };
      },
    });
  const pages = [];
  let url = startUrl;
  do {
    const page = await retryGitHub(() => requestPage(url), {
      operationName: options.operationName ?? `GET ${endpoint}`,
      maxAttempts: options.maxAttempts,
      totalWaitBudgetSeconds: options.totalWaitBudgetSeconds,
      readPrimaryRateLimit: rateLimit,
      onProgress: options.onProgress,
      sleepSeconds: options.sleepSeconds,
      nowSeconds: options.nowSeconds,
      jitterSeconds: options.jitterSeconds,
      random: options.random,
    });
    pages.push(page.data);
    if (!options.paginate) break;
    const next = /<([^>]+)>;\s*rel="next"/.exec(page.link ?? '');
    url = next?.[1];
  } while (url);
  if (!options.paginate) return pages[0];
  return pages.flat();
}

module.exports = {
  GitHubRetryDeferredError,
  classifyGitHubError,
  computeWaitSeconds,
  formatRetryProgress,
  readPrimaryRateLimit,
  requestGitHubApi,
  retryGitHub,
};

async function main(argv) {
  if (argv[0] !== 'get' || !argv[1]) {
    throw new Error('usage: github-api-resilience.cjs get ENDPOINT [--paginate]');
  }
  const data = await requestGitHubApi(argv[1], {
    token: process.env.GH_TOKEN || process.env.GITHUB_TOKEN,
    paginate: argv.includes('--paginate'),
    operationName: `read ${argv[1]}`,
    totalWaitBudgetSeconds: 900,
    onProgress: (event) => console.error(formatRetryProgress(event)),
  });
  process.stdout.write(`${JSON.stringify(data)}\n`);
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = error?.code === 84 ? 84 : 1;
  });
}
