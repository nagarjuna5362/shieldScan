const crypto = require('crypto');
const axios = require('axios');

const store = new Map();
const EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 24 hours
const EXPIRATION_TIME_SECONDS = 24 * 60 * 60; // 24 hours in seconds

// Support Vercel KV or Upstash Redis REST credentials
const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

async function saveReport(report) {
  const uuid = crypto.randomUUID();

  if (kvUrl && kvToken) {
    try {
      // Clean up URL formatting (ensure no trailing slash or /v1 suffix issues)
      const baseUrl = kvUrl.endsWith('/') ? kvUrl.slice(0, -1) : kvUrl;
      const cleanUrl = baseUrl.endsWith('/pipeline') ? baseUrl.replace('/pipeline', '') : baseUrl;
      
      // Store report data serialized as JSON under report:uuid key with a 24-hour expiration (EX 86400)
      await axios.post(
        cleanUrl,
        ['SET', `report:${uuid}`, JSON.stringify(report), 'EX', String(EXPIRATION_TIME_SECONDS)],
        {
          headers: {
            Authorization: `Bearer ${kvToken}`,
            'Content-Type': 'application/json',
          },
        }
      );
      return uuid;
    } catch (err) {
      console.error('[KV STORE ERROR] Failed to save report to Redis:', err.message);
      // Fall back to in-memory map on error
    }
  }

  // Fallback in-memory implementation
  store.set(uuid, {
    report,
    createdAt: Date.now(),
  });

  setTimeout(() => {
    store.delete(uuid);
  }, EXPIRATION_TIME);

  return uuid;
}

async function getReport(uuid) {
  if (kvUrl && kvToken) {
    try {
      const baseUrl = kvUrl.endsWith('/') ? kvUrl.slice(0, -1) : kvUrl;
      const cleanUrl = baseUrl.endsWith('/pipeline') ? baseUrl.replace('/pipeline', '') : baseUrl;

      const res = await axios.post(
        cleanUrl,
        ['GET', `report:${uuid}`],
        {
          headers: {
            Authorization: `Bearer ${kvToken}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (res.data && res.data.result) {
        return JSON.parse(res.data.result);
      }
      return null;
    } catch (err) {
      console.error('[KV STORE ERROR] Failed to retrieve report from Redis:', err.message);
      // Fall back to check in-memory map on error
    }
  }

  const data = store.get(uuid);
  if (!data) return null;

  if (Date.now() - data.createdAt > EXPIRATION_TIME) {
    store.delete(uuid);
    return null;
  }

  return data.report;
}

// Memory cleaner for in-memory fallback
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
