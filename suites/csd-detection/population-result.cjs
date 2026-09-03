'use strict';

function classifyPopulationResult(expectation, sessions) {
  if (!['loaded', 'blocked'].includes(expectation)) {
    throw new Error('EXPECT_SCRIPT must be either loaded or blocked');
  }
  if (!Array.isArray(sessions)) {
    throw new TypeError('sessions must be an array');
  }

  const counts = {
    total: sessions.length,
    completed: sessions.filter((item) => item.completed).length,
    loaded: sessions.filter((item) => item.scriptState === 'loaded').length,
    blocked: sessions.filter((item) => item.scriptState === 'blocked').length,
    unknown: sessions.filter((item) => !['loaded', 'blocked'].includes(item.scriptState)).length,
  };
  let classification = 'unknown';
  if (counts.loaded > 0 && counts.blocked > 0) classification = 'mixed';
  else if (counts.loaded === counts.total && counts.total > 0) classification = 'loaded';
  else if (counts.blocked === counts.total && counts.total > 0) classification = 'blocked';

  return {
    expectation,
    classification,
    passed:
      counts.total > 0 &&
      counts.completed === counts.total &&
      counts.unknown === 0 &&
      classification === expectation,
    counts,
  };
}

module.exports = { classifyPopulationResult };
