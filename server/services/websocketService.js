'use strict';

let wss = null;

function initWebSocket(server) {
  let WebSocketServer = null;
  try { WebSocketServer = require('ws').WebSocketServer; } catch { /* ws not installed */ }
  if (!WebSocketServer) return false;
  wss = new WebSocketServer({ server });
  wss.on('connection', ws => { ws.on('error', () => {}); });
  return true;
}

function broadcastAlert(payload) {
  if (!wss) return;
  const msg = JSON.stringify(payload);
  wss.clients.forEach(client => { if (client.readyState === 1) client.send(msg); });
}

module.exports = { initWebSocket, broadcastAlert };
