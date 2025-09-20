import 'dotenv/config';
import http from 'http';
import https from 'https';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { logger } from './logger.js';
import { prisma } from './prisma.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 8443);

// Health HTTP
app.get('/healthz', (_req, res) => res.send('ok'));

// DB health
app.get('/health/db', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ db: 'ok' });
  } catch (e: any) {
    logger.error(e, 'DB health failed');
    res.status(500).json({ db: 'error', error: String(e?.message || e) });
  }
});

// Версия API
app.get('/api/version', (_req, res) => res.json({ name: 'edge-vpn-server', version: '0.2.0' }));

// HTTP(S) server с опциональным TLS
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

// WebSocket скелет
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