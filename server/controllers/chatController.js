'use strict';

const https = require('https');
const { GROQ_API_KEY } = require('../config');
const { jsonOk, jsonError, parseBody } = require('../middleware/http');
const { requireAuth } = require('../middleware/auth');

async function chat(req, res) {
  const actor = await requireAuth(req, res);
  if (!actor) return;

  if (!GROQ_API_KEY) {
    return jsonError(res, 503, 'AI chat not configured. Add GROQ_API_KEY to server/.env');
  }

  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');

  const { messages } = body;
  if (!Array.isArray(messages) || messages.length === 0)
    return jsonError(res, 400, 'messages array required.');

  const cleaned = messages.slice(-20).map(m => ({
    role:    m.role === 'assistant' ? 'assistant' : 'user',
    content: String(m.content || '').slice(0, 2000),
  }));

  const payload = JSON.stringify({
    model:      'llama-3.3-70b-versatile',
    max_tokens: 1024,
    messages: [
      {
        role:    'system',
        content: 'You are PhishGuard AI, a cybersecurity assistant embedded in the PhishGuard phishing detection platform. Help users understand phishing threats, interpret scan results, explain detection techniques, and give practical security advice. Be concise, friendly, and security-focused. If asked something unrelated to security, gently redirect to security topics.',
      },
      ...cleaned,
    ],
  });

  try {
    const result = await new Promise((resolve, reject) => {
      const opts = {
        hostname: 'api.groq.com',
        path:     '/openai/v1/chat/completions',
        method:   'POST',
        headers:  {
          'Content-Type':   'application/json',
          'Authorization':  `Bearer ${GROQ_API_KEY}`,
          'Content-Length': Buffer.byteLength(payload),
        },
      };
      const r = https.request(opts, resp => {
        let data = '';
        resp.on('data', c => data += c);
        resp.on('end', () => {
          try { resolve({ status: resp.statusCode, body: JSON.parse(data) }); }
          catch { resolve({ status: resp.statusCode, body: { error: { message: data } } }); }
        });
      });
      r.on('error', reject);
      r.write(payload);
      r.end();
    });

    if (result.status !== 200)
      return jsonError(res, 502, result.body?.error?.message || 'AI service error.');

    const reply = result.body.choices?.[0]?.message?.content || 'No response received.';
    jsonOk(res, { reply });
  } catch (err) {
    jsonError(res, 502, 'Failed to reach AI service: ' + err.message);
  }
}

module.exports = { chat };
