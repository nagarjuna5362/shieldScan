const crypto = require('crypto');

const store = new Map();
const EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 24 hours

function saveReport(report) {
  const uuid = crypto.randomUUID();
  store.set(uuid, {
    report,
    createdAt: Date.now(),
  });

  setTimeout(() => {
    store.delete(uuid);
  }, EXPIRATION_TIME);

  return uuid;
}

function getReport(uuid) {
  const data = store.get(uuid);
  if (!data) return null;

  if (Date.now() - data.createdAt > EXPIRATION_TIME) {
    store.delete(uuid);
    return null;
  }

  return data.report;
}

setInterval(() => {
  const now = Date.now();
  for (const [uuid, data] of store.entries()) {
    if (now - data.createdAt > EXPIRATION_TIME) {
      store.delete(uuid);
    }
  }
}, 60 * 60 * 1000);

module.exports = {
  saveReport,
  getReport,
};
