// Track application requests so native form navigation does not cancel its own work.
function observeRequests(page) {
  const state = { pending: new Set(), changed: Date.now() };
  page.on('request', (request) => {
    if (new URL(request.url()).pathname.includes('/socket.io/')) return;
    state.pending.add(request);
    state.changed = Date.now();
  });
  for (const event of ['requestfinished', 'requestfailed'])
    page.on(event, (request) => {
      state.pending.delete(request);
      state.changed = Date.now();
    });
  return state;
}
async function settleRequests(state, timeoutMs = 15000, quietMs = 500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!state.pending.size && Date.now() - state.changed >= Math.min(quietMs, timeoutMs / 2)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('Application requests did not finish before browser navigation or cleanup');
}
function childHeaders(marker = process.env.TGEN_CHILD_MARKER || '') {
  if (!marker) return {};
  if (!/^[a-z0-9-]{1,80}$/.test(marker)) throw new Error('Invalid owned browser child marker');
  return { 'X-TGen-Child': marker };
}
module.exports = { observeRequests, settleRequests, childHeaders };

async function installSocketDrain(page) {
  await page.addInitScript(() => {
    const NativeSocket = globalThis.WebSocket;
    globalThis.__tgenSockets = new Set();
    globalThis.WebSocket = class extends NativeSocket {
      constructor(...args) {
        super(...args);
        globalThis.__tgenSockets.add(this);
        this.addEventListener('close', () => globalThis.__tgenSockets.delete(this));
      }
    };
  });
}
async function closeSockets(page) {
  await page.evaluate(async () => {
    await Promise.all(
      Array.from(
        globalThis.__tgenSockets || [],
        (socket) =>
          new Promise((resolve, reject) => {
            if (socket.readyState === 3) return resolve();
            const timeout = setTimeout(() => reject(new Error('Native WebSocket did not close normally')), 10000);
            socket.addEventListener(
              'close',
              () => {
                clearTimeout(timeout);
                resolve();
              },
              { once: true },
            );
            socket.close(1000, 'Native browser workload complete');
          }),
      ),
    );
  });
}
module.exports.installSocketDrain = installSocketDrain;
module.exports.closeSockets = closeSockets;
