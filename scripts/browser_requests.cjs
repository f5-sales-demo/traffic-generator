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
async function settleRequests(state, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!state.pending.size && Date.now() - state.changed >= Math.min(500, timeoutMs / 2)) return;
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
