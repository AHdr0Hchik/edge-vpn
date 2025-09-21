import 'dotenv/config';
import http from 'http';
import https from 'https';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import { WebSocketServer, WebSocket } from 'ws';
import { z } from 'zod';

import { logger } from './logger.js';
import { prisma } from './prisma.js';
import { requireAuth, requireAdmin, signJwt, hashSecret, compareSecret } from './auth.js';
import { pickVpnServer, allocateAddressCidr } from './ipam.js';
import { gwUpsertPeer } from './gateway.js';
import bcrypt from "bcryptjs"


const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 8443);
const WG_DEFAULT_DNS = (process.env.WG_DEFAULT_DNS || '1.1.1.1').split(',').map((x) => x.trim());

/* ================= Health ================= */

app.get('/healthz', (_req, res) => res.send('ok'));
app.get('/health/db', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ db: 'ok' });
  } catch (e: any) {
    logger.error(e, 'DB health failed'); res.status(500).json({ db: 'error', error: String(e?.message || e) });
  }
});
app.get('/api/version', (_req, res) => res.json({ name: 'edge-vpn-server', version: '0.3.0' }));

/* ================= Auth (users) ================= */

app.post('/api/auth/register', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(6) });
  const { email, password } = schema.parse(req.body);
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: 'email exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({ data: { email, passwordHash: hash } });
  const token = signJwt(user.id);
  res.json({ token });
});

app.post('/api/auth/login', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
  const { email, password } = schema.parse(req.body);
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'invalid creds' });
  const bcrypt = await import('bcryptjs');
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid creds' });
  const token = signJwt(user.id);
  res.json({ token });
});

/* ================= User APIs ================= */

app.get('/api/devices', requireAuth, async (req, res) => {
  const userId = (req as any).userId as string;
  const list = await prisma.device.findMany({
    where: { ownerId: userId },
    include: { speedTier: true, peer: { include: { server: true } } }
  });
  res.json(list.map((d: any) => ({
    id: d.id,
    name: d.name,
    lastSeen: d.lastSeen,
    vpnEnabled: d.vpnEnabled,
    speedTier: d.speedTier?.name,
    connected: wsConns.has(d.id),
    vpnServer: d.peer ? { id: d.peer.serverId, endpoint: d.peer.server.endpoint, location: d.peer.server.location } : null
  })));
});

app.post('/api/devices/:id/vpn', requireAuth, async (req, res) => {
  const schema = z.object({ enabled: z.boolean() });
  const { enabled } = schema.parse(req.body);
  const dev = await findUserDevice(req);
  if (!dev) return res.status(404).json({ error: 'not found' });
  await prisma.device.update({ where: { id: dev.id }, data: { vpnEnabled: enabled } });
  await pushPolicy(dev.id);
  res.json({ ok: true });
});

app.get('/api/devices/:id/bypass-domains', requireAuth, async (req, res) => {
  const dev = await findUserDevice(req);
  if (!dev) return res.status(404).json({ error: 'not found' });
  const domains = await prisma.bypassDomain.findMany({ where: { deviceId: dev.id } });
  res.json(domains.map(d => d.domain));
});

app.post('/api/devices/:id/bypass-domains', requireAuth, async (req, res) => {
  const schema = z.object({ domains: z.array(z.string()).max(200) });
  const { domains } = schema.parse(req.body);
  const dev = await findUserDevice(req);
  if (!dev) return res.status(404).json({ error: 'not found' });
  const list = sanitizeDomains(domains);
  await prisma.$transaction([
    prisma.bypassDomain.deleteMany({ where: { deviceId: dev.id } }),
    ...(list.length
      ? [prisma.bypassDomain.createMany({
          data: list.map(domain => ({ deviceId: dev.id, domain }))
        })]
      : [])
  ]);
  await pushPolicy(dev.id);
  res.json({ ok: true, count: list.length });
});

/* ================= Admin APIs ================= */

// Добавить VPN-сервер (шлюз)
app.post('/api/admin/servers', requireAdmin, async (req, res) => {
  const schema = z.object({
    name: z.string().min(1),
    endpoint: z.string().min(3),  // host:port
    publicKey: z.string().min(8),
    apiUrl: z.string().url(),
    apiToken: z.string().min(6),
    ipPoolCidr: z.string().min(8),
    location: z.string().optional()
  });
  const data = schema.parse(req.body);
  const s = await prisma.vpnServer.create({ data: { ...data, wgInterface: 'wg0', enabled: true } });
  res.json(s);
});

app.get('/api/admin/servers', requireAdmin, async (_req, res) => {
  const servers = await prisma.vpnServer.findMany({ include: { peers: true } });
  res.json(servers);
});

// Зарегистрировать устройство (привязка к пользователю)
app.post('/api/admin/devices', requireAdmin, async (req, res) => {
  const schema = z.object({
    ownerEmail: z.string().email(),
    deviceId: z.string().min(3),
    deviceSecret: z.string().min(6),
    name: z.string().optional()
  });
  const { ownerEmail, deviceId, deviceSecret, name } = schema.parse(req.body);
  const owner = await prisma.user.findUnique({ where: { email: ownerEmail } });
  if (!owner) return res.status(400).json({ error: 'owner not found' });
  const secretHash = await hashSecret(deviceSecret);
  const dev = await prisma.device.create({
    data: {
      id: deviceId,
      ownerId: owner.id,
      secretHash,
      name
    }
  });
  res.json({ id: dev.id, ownerId: dev.ownerId, name: dev.name });
});

/* ================= WSS: устройства ================= */

type DeviceConn = { id: string; ws: WebSocket };
const wsConns = new Map<string, DeviceConn>();

function closeExisting(id: string) {
  const prev = wsConns.get(id);
  if (prev) try { prev.ws.close(); } catch {}
}

function pushTo(id: string, payload: any) {
  const conn = wsConns.get(id);
  if (!conn) return false;
  try {
    conn.ws.send(JSON.stringify(payload));
    return true;
  } catch (e) {
    logger.error(e, 'WS send failed');
    return false;
  }
}

let server: http.Server | https.Server;
const certPath = process.env.TLS_CERT; const keyPath = process.env.TLS_KEY;
if (certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  server = https.createServer({ cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }, app);
  logger.info('TLS enabled');
} else {
  server = http.createServer(app);
  logger.warn('TLS disabled — dev mode');
}

const wss = new WebSocketServer({ noServer: true });
(server as any).on('upgrade', async (req: http.IncomingMessage, socket: { destroy: () => void; }, head: Buffer<ArrayBufferLike>) => {
  try {
    const url = new URL(req.url || '', `http://${req.headers.host}`);
    if (url.pathname !== '/ws') return socket.destroy();
    const deviceId = url.searchParams.get('device_id') || '';
    const token = url.searchParams.get('token') || '';
    if (!deviceId || !token) return socket.destroy();

    const dev = await prisma.device.findUnique({ where: { id: deviceId } });
    if (!dev) return socket.destroy();
    const ok = await compareSecret(token, dev.secretHash);
    if (!ok) return socket.destroy();

    wss.handleUpgrade(req, socket as any, head, (ws) => {
      wss.emit('connection', ws, req, deviceId);
    });
  } catch {
    try { socket.destroy(); } catch {}
  }
});

wss.on('connection', (ws: WebSocket, _req: any, deviceId: string) => {
  closeExisting(deviceId);
  wsConns.set(deviceId, { id: deviceId, ws });
  logger.info({ deviceId }, 'WS connected');

  // Keepalive ping
  const pingIv = setInterval(() => {
    try { ws.ping(); } catch {}
  }, 30000);

  ws.on('close', () => {
    clearInterval(pingIv);
    if (wsConns.get(deviceId)?.ws === ws) wsConns.delete(deviceId);
    logger.info({ deviceId }, 'WS closed');
  });

  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'hello') {
        const pubKey = msg.pubKey as string | undefined;
        await prisma.device.update({
          where: { id: deviceId },
          data: { lastSeen: new Date(), ...(pubKey ? { publicKey: pubKey } : {}) }
        });

        // Назначить сервер/адрес и создать peer (если отсутствует)
        let peer = await prisma.vpnPeer.findUnique({ where: { deviceId }, include: { server: true } });
        if (!peer) {
          const server = await pickVpnServer();
          if (!server) {
            logger.error('No VPN servers enabled');
            return;
          }
          const addressCidr = await allocateAddressCidr(server.id, server.ipPoolCidr);
          const device = await prisma.device.findUnique({ where: { id: deviceId }, include: { speedTier: true } });
          const rate = device?.speedTier?.rateMbps ?? 40;
          if (!device?.publicKey) {
            logger.warn({ deviceId }, 'No device publicKey in hello; profile will be sent but gw-agent may fail');
          } else {
            try {
              await gwUpsertPeer(server, device.publicKey, addressCidr, rate);
            } catch (e) {
              logger.error(e, 'gwUpsertPeer failed (will proceed with profile push)');
            }
          }
          peer = await prisma.vpnPeer.create({
            data: { deviceId, serverId: server.id, addressCidr, rateMbps: rate },
            include: { server: true }
          });
        }

        // Пуш профиля
        await pushProfile(deviceId, peer);
        await pushPolicy(deviceId);
      } else if (msg.type === 'heartbeat') {
        await prisma.device.update({ where: { id: deviceId }, data: { lastSeen: new Date() } }).catch(() => {});
        await prisma.deviceHeartbeat.create({ data: { deviceId, data: msg.data || {} } }).catch(() => {});
      } else if (msg.type === 'result') {
        logger.info({ deviceId, action: msg.action, ok: msg.ok, error: msg.error }, 'result');
      } else {
        logger.info({ deviceId, msg }, 'WS message');
      }
    } catch (e) {
      logger.error(e, 'WS message error');
    }
  });
});

async function pushProfile(deviceId: string, peer?: any) {
  if (!peer) peer = await prisma.vpnPeer.findUnique({ where: { deviceId }, include: { server: true } });
  if (!peer) return;
  const payload = {
    type: 'action',
    action: 'profile',
    data: {
      endpoint: peer.server.endpoint,
      serverPublicKey: peer.server.publicKey,
      addressCidr: peer.addressCidr,
      dns: WG_DEFAULT_DNS,
      allowedIPs: ['0.0.0.0/0', '::/0'],
      persistentKeepalive: 25
    }
  };
  const sent = pushTo(deviceId, payload);
  if (sent) logger.info({ deviceId }, 'profile pushed');
  else logger.warn({ deviceId }, 'profile push failed (no WS)');
}

async function findUserDevice(req: express.Request) {
  const userId = (req as any).userId as string;
  const id = req.params.id;
  return prisma.device.findFirst({ where: { id, ownerId: userId } });
}

function sanitizeDomains(domains: string[]): string[] {
  const out = new Set<string>();
  for (const d of domains) {
    const s = (d || '').trim().toLowerCase();
    if (!s) continue;
    // примитивная проверка FQDN: буквы/цифры/дефис/точки, минимум одна точка
    if (!/^[a-z0-9.-]+$/.test(s) || s.indexOf('.') < 0) continue;
    out.add(s);
  }
  return Array.from(out).slice(0, 200);
}

async function pushPolicy(deviceId: string) {
  const dev = await prisma.device.findUnique({
    where: { id: deviceId },
    include: { bypassDomains: true }
  });
  if (!dev) return;
  const payload = {
    type: 'action',
    action: 'policy',
    data: {
      vpnEnabled: dev.vpnEnabled,
      bypassDomains: dev.bypassDomains.map(b => b.domain)
    }
  };
  const sent = pushTo(deviceId, payload);
  if (!sent) logger.warn({ deviceId }, 'policy push skipped (no WS)');
}

server.listen(PORT, () => logger.info(`Server listening on ${PORT}`));