import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { executionArgs } from '../suites/csd-violations/continuous.mjs';
import { SCENARIO_NAMES } from '../suites/csd-violations/scenarios.mjs';

const config = { TARGET_URL: 'https://client-side-defense.f5-sales-demo.com' };

// Explicit host integration, outside tests/test-*.sh unit discovery. Missing tools
// or sudo policy must fail, not silently skip. It never starts units or traffic.
function command(binary, args, options = {}) {
  const response = spawnSync(binary, args, { encoding: 'utf8', ...options });
  assert.equal(response.status, 0, response.stderr || response.error?.message);
  return response.stdout.trim();
}
test('real sudo env reset cannot discard per-run fields or inherit credentials', async () => {
  const env = {
    ...config,
    RUN_ID: 'csd-boundary',
    CSD_SCENARIO: SCENARIO_NAMES[0],
    DISPLAY: ':100',
    PATH: '/usr/bin:/bin',
    HOME: '/tmp',
    RUNTIME_ENV: '/etc/traffic-generator/runtime.env',
    AWS_SECRET_ACCESS_KEY: 'synthetic-secret',
    XCSH_API_TOKEN: 'synthetic-token',
  };
  const script = `printf "%s|%s|%s|%s|%s" "$RUN_ID" "$CSD_SCENARIO" "$DISPLAY" "\${AWS_SECRET_ACCESS_KEY-unset}" "\${XCSH_API_TOKEN-unset}"`;
  // The old process boundary loses the assignment under the real sudo policy.
  const old = command(
    '/usr/bin/sudo',
    ['-n', '-u', 'nobody', '--', '/bin/bash', '-c', `printf "%s" "\${RUN_ID-unset}"`],
    { env },
  );
  assert.equal(old, 'unset');
  const args = executionArgs({ runId: env.RUN_ID, scenario: env.CSD_SCENARIO, env, args: ['-c', script] });
  assert.ok(!args.some((arg) => arg.includes('synthetic-secret') || arg.includes('synthetic-token')));
  args[1] = 'nobody'; // same real privilege boundary, no test account installation
  const output = command('/usr/bin/sudo', ['-n', ...args], { env });
  assert.equal(output, `${env.RUN_ID}|${env.CSD_SCENARIO}|:100|unset|unset`);
});

test('actual systemd and logrotate parse the canonical cloud-init units', async (t) => {
  assert.equal(process.platform, 'linux');
  const root = await mkdtemp(join(tmpdir(), 'csd-host-integration-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const template = await readFile(new URL('../terraform/aws/cloud-init.tftpl', import.meta.url), 'utf8');
  function extract(path) {
    const marker = `  - path: ${path}\n`;
    const start = template.indexOf(marker);
    assert.ok(start >= 0, `Missing ${path}`);
    const body = template.slice(start + marker.length).split('    content: |\n')[1];
    assert.ok(body);
    const content =
      body
        .split(/\n(?: {2}- path:|runcmd:)/)[0]
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => {
          assert.ok(line.startsWith('      '));
          return line.slice(6);
        })
        .join('\n') + '\n';
    assert.ok(!content.includes('${'), 'Unit must match rendered template exactly');
    return content;
  }
  const units = ['csd-continuous.service', 'csd-continuous.timer', 'csd-worker-health.service', 'csd-xvfb.service'];
  const directory = join(root, 'etc/systemd/system');
  await mkdir(directory, { recursive: true });
  for (const unit of units) await writeFile(join(directory, unit), extract(`/etc/systemd/system/${unit}`));
  for (const executable of ['opt/node/bin/node', 'usr/bin/Xvfb', 'usr/local/bin/csd-worker-health-check', 'bin/true']) {
    const destination = join(root, executable);
    await mkdir(destination.slice(0, destination.lastIndexOf('/')), { recursive: true });
    await cp('/bin/true', destination);
  }
  for (const target of ['sysinit', 'basic', 'shutdown', 'network', 'network-online', 'timers', 'multi-user'])
    await writeFile(join(directory, `${target}.target`), '[Unit]\nDescription=Unit syntax fixture\n');
  await writeFile(
    join(directory, 'systemd-tmpfiles-setup.service'),
    '[Unit]\nDescription=Tmpfiles ordering fixture\n[Service]\nType=oneshot\nExecStart=/bin/true\n',
  );
  command('/usr/bin/systemd-analyze', [`--root=${root}`, '--man=no', 'verify', ...units]);
  const rotation = join(root, 'logrotate.conf');
  await writeFile(rotation, extract('/etc/logrotate.d/csd-traffic-generator'));
  command('/usr/sbin/logrotate', ['--debug', rotation]);
});
