import 'dotenv/config';
import http from 'http';
import https from 'https';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { logger } from './logger.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 8443);

// Health
app.get('/healthz', (_req, res) => res.send('ok'));

// Placeholder API (для последующих этапов)
app.get('/api/version', (_req, res) => res.json({ name: 'edge-vpn-server', version: '0.1.0' }));

// HTTP(S) server с опциональным TLS (для WSS)
let server: http.Server | https.Server;
const certPath = process.env.TLS_CERT;
const keyPath = process.env.TLS_KEY;

if (certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  server = https.createServer({ cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }, app);
  logger.info('TLS enabled');
} else {
  server = http.createServer(app);
  logger.warn('TLS disabled — dev mode');
}

// WebSocket скелет (позже: авторизация по device_id/secret)
const wss = new WebSocketServer({ noServer: true });
(server as any).on('upgrade', (req: http.IncomingMessage, socket: { destroy: () => any; }, head: Buffer<ArrayBufferLike>) => {
  const url = new URL(req.url || '', `http://${req.headers.host}`);
  if (url.pathname !== '/ws') return socket.destroy();
  wss.handleUpgrade(req, socket as any, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  logger.info('WS connected');
  ws.on('message', (msg) => logger.info({ msg: msg.toString() }, 'WS message'));
  ws.on('close', () => logger.info('WS closed'));
});

server.listen(PORT, () => logger.info(`Server listening on ${PORT}`));