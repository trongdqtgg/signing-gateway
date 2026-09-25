'use strict';
const crypto = require('node:crypto');
const http = require('node:http');

function proof(secret, timestamp) {
  return crypto.createHmac('sha256', secret).update(`prepare-update:${timestamp}`).digest('hex');
}

function createUpdateLifecycle(cfg) {
  let active = 0;
  let pausedUntil = 0;
  let preparing = false;
  return {
    enter() {
      if (Date.now() < pausedUntil) return false;
      active++;
      return true;
    },
    leave() { active--; },
    async prepare(req) {
      const address = req.socket.remoteAddress;
      const timestamp = req.headers['x-update-time'];
      const signature = req.headers['x-update-proof'];
      const localHost = /^(127\.0\.0\.1|\[::1\])(:\d+)?$/.test(req.headers.host || '');
      if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(address) || !localHost || req.headers.origin ||
          req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip'] ||
          !cfg.hisSharedSecret || !/^\d+$/.test(timestamp || '') ||
          Math.abs(Date.now() - Number(timestamp)) > 30000 || !/^[a-f0-9]{64}$/.test(signature || '') ||
          !crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(proof(cfg.hisSharedSecret, timestamp), 'hex'))) {
        return { status: 403, body: { error: 'UPDATE_NOT_AUTHORIZED' } };
      }
      if (preparing) return { status: 409, body: { error: 'UPDATE_PREPARING' } };
      preparing = true;
      // Automatically recover if setup fails or is cancelled after preparation.
      pausedUntil = Date.now() + 120000;
      try {
        const deadline = Date.now() + 60000;
        while (active && Date.now() < deadline) await new Promise(r => setTimeout(r, 100));
        if (active) {
          pausedUntil = 0;
          return { status: 409, body: { error: 'SIGNING_BUSY' } };
        }
        return { status: 200, body: { ready: true } };
      } finally { preparing = false; }
    }
  };
}

async function prepareUpdate(cfg) {
  const timestamp = String(Date.now());
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: cfg.host === '::1' ? '::1' : '127.0.0.1', port: cfg.port,
      path: '/internal/update/prepare', method: 'POST', timeout: 65000,
      headers: { 'x-update-time': timestamp, 'x-update-proof': proof(cfg.hisSharedSecret || '', timestamp) }
    }, res => { res.resume(); res.on('end', () => res.statusCode === 200 ? resolve() : reject(new Error(`Update preparation: HTTP ${res.statusCode}`))); });
    req.on('timeout', () => req.destroy(new Error('Update preparation timeout')));
    req.on('error', e => e.code === 'ECONNREFUSED' ? resolve() : reject(e));
    req.end();
  });
}
module.exports = { createUpdateLifecycle, prepareUpdate, proof };
