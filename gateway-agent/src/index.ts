import 'dotenv/config';
import express from 'express';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';

const run = promisify(execFile);
const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 9000);
const API_TOKEN = process.env.API_TOKEN || 'changeme';
const WG_IF = process.env.WG_IF || 'wg0';
let WAN_IF = process.env.WAN_IF || '';
const MARK_TABLE = process.env.MARK_TABLE || 'fwmark';
const DEFAULT_RATE = Number(process.env.CLASS_DEFAULT_RATE || 1000);

function auth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (token !== API_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  return next();
}

async function detectWan(): Promise<string> {
  if (WAN_IF) return WAN_IF;
  try {
    const { stdout } = await run('sh', ['-c', "ip route show default | awk '/default/ {print $5; exit}'"]);
    WAN_IF = stdout.trim() || 'eth0';
  } catch {
    WAN_IF = 'eth0';
  }
  return WAN_IF;
}

async function ensureSysctl() {
  await run('sysctl', ['-w', 'net.ipv4.ip_forward=1']).catch(() => {});
  await run('sysctl', ['-w', 'net.ipv6.conf.all.forwarding=1']).catch(() => {});
}

async function ensureWgUp() {
  // Если wg0 не поднят — поднять
  const { stdout } = await run('sh', ['-c', `wg show ${WG_IF} 2>/dev/null || true`]);
  if (!stdout) {
    await run('wg-quick', ['up', WG_IF]).catch(() => {});
  }
}

async function ensureNat(wan: string) {
  // NAT через nftables: ip nat postrouting -> masquerade на WAN
  await run('nft', ['list', 'table', 'ip', 'nat']).catch(async () => {
    await run('nft', ['add', 'table', 'ip', 'nat']);
  });
  await run('nft', ['list', 'chain', 'ip', 'nat', 'postrouting']).catch(async () => {
    await run('nft', ['add', 'chain', 'ip', 'nat', 'postrouting', '{', 'type', 'nat', 'hook', 'postrouting', 'priority', '100', ';', 'policy', 'accept', ';', '}']);
  });
  // Добавить правило masquerade, если его нет
  const { stdout } = await run('nft', ['list', 'chain', 'ip', 'nat', 'postrouting']);
  if (!stdout.includes(`oifname "${wan}" masquerade`)) {
    await run('nft', ['add', 'rule', 'ip', 'nat', 'postrouting', 'oifname', wan, 'masquerade']).catch(() => {});
  }
}

function classIdFromKey(pubKey: string): string {
  // детерминируем class id по pubKey (1:2..1:60000)
  let h = 0;
  for (let i = 0; i < pubKey.length; i++) {
    h = (h * 33) ^ pubKey.charCodeAt(i);
    h |= 0;
  }
  const id = Math.abs(h % 60000) + 1;
  return `1:${id}`;
}

function markFromKey(pubKey: string): string {
  // 0xC000..0xFFFF диапазон
  let h = 0;
  for (let i = 0; i < pubKey.length; i++) {
    h = (h * 33) ^ pubKey.charCodeAt(i);
    h |= 0;
  }
  const n = (Math.abs(h) % 16383) + 0x4000; // 0x4000..0x7FFF
  return `0x${n.toString(16)}`;
}

async function ensureQdisc(wan: string) {
  // Корневой HTB на WAN: 1: default 999
  const show = await run('tc', ['qdisc', 'show', 'dev', wan]).catch(() => ({ stdout: '' as string }));
  if (!show.stdout.includes('htb 1:')) {
    await run('tc', ['qdisc', 'add', 'dev', wan, 'root', 'handle', '1:', 'htb', 'default', '999']).catch(() => {});
    // Класс по умолчанию (широкий)
    await run('tc', ['class', 'add', 'dev', wan, 'parent', '1:', 'classid', '1:999', 'htb',
      'rate', `${DEFAULT_RATE}mbit`, 'ceil', `${DEFAULT_RATE}mbit`]).catch(() => {});
  }
}

async function ensureMarkTable() {
  // Таблица inet MARK_TABLE, цепочка forward (mangle priority), создаёт метки по src=peer
  await run('nft', ['list', 'table', 'inet', MARK_TABLE]).catch(async () => {
    await run('nft', ['add', 'table', 'inet', MARK_TABLE]);
  });
  // Создадим цепочку forward, если нет
  const ok = await run('nft', ['list', 'chain', 'inet', MARK_TABLE, 'forward'])
    .then(() => true).catch(() => false);
  if (!ok) {
    await run('nft', ['add', 'chain', 'inet', MARK_TABLE, 'forward',
      '{', 'type', 'filter', 'hook', 'forward', 'priority', '-150', ';', 'policy', 'accept', ';', '}']);
  }
}

async function upsertPeer(pubKey: string, addressCidr: string, rateMbps: number, deviceId?: string) {
  await ensureSysctl();
  await ensureWgUp();
  const wan = await detectWan();
  await ensureNat(wan);
  await ensureQdisc(wan);
  await ensureMarkTable();

  // 1) WireGuard peer
  // allowed-ips = addressCidr; keepalive 25
  await run('wg', ['set', WG_IF, 'peer', pubKey, 'allowed-ips', addressCidr, 'persistent-keepalive', '25'])
    .catch(async (e) => {
      // Если wg0 ещё не поднят — попробуем поднять и повторить
      await ensureWgUp();
      await run('wg', ['set', WG_IF, 'peer', pubKey, 'allowed-ips', addressCidr, 'persistent-keepalive', '25']);
    });

  // 2) nft mark для этого peer: трафик FORWARD iif=wg0 ip saddr=<peerIP> -> mark=0xNN
  const ip = addressCidr.split('/')[0];
  const mark = markFromKey(pubKey);
  const comment = deviceId ? `peer_${deviceId}` : `peer_${ip}`;
  // Удалим возможные старые правила с этим ip/mark (мягко), затем добавим
  // Простой путь: добавляем, дубли не критичны, но стараемся избегать дублей:
  const { stdout: chain } = await run('nft', ['list', 'chain', 'inet', MARK_TABLE, 'forward']);
  if (!chain.includes(ip)) {
    await run('nft', ['add', 'rule', 'inet', MARK_TABLE, 'forward',
      'iifname', WG_IF, 'ip', 'saddr', ip, 'meta', 'mark', 'set', mark, 'comment', comment]).catch(() => {});
    // IPv6 аналог можно добавить при необходимости: iifname wg0 ip6 saddr ...
  }

  // 3) tc HTB класс и фильтр по fwmark на WAN
  const classId = classIdFromKey(pubKey);
  // Класс
  await run('tc', ['class', 'replace', 'dev', wan, 'parent', '1:', 'classid', classId, 'htb',
    'rate', `${rateMbps}mbit`, 'ceil', `${rateMbps}mbit`]);
  // Фильтры для IPv4/IPv6 по fwmark
  await run('tc', ['filter', 'replace', 'dev', wan, 'protocol', 'ip', 'parent', '1:', 'prio', '1',
    'handle', mark, 'fw', 'flowid', classId]).catch(() => {});
  await run('tc', ['filter', 'replace', 'dev', wan, 'protocol', 'ipv6', 'parent', '1:', 'prio', '1',
    'handle', mark, 'fw', 'flowid', classId]).catch(() => {});
}

async function deletePeer(pubKey: string, addressCidr: string) {
  const wan = await detectWan();
  // Удалим peer из WG
  await run('wg', ['set', WG_IF, 'peer', pubKey, 'remove']).catch(() => {});
  // Удалим nft‑правило по saddr
  const ip = addressCidr.split('/')[0];
  // Не знаем ID правила — перечитать цепь и пересоздать без него сложно.
  // Для MVP: flush and rebuild — но это затронет всех. Поэтому мягкий способ:
  // Добавим метку "expired" на совпадения и периодически flush будем делать внешним скриптом.
  // Здесь попробуем удалить через grep -n (менее надёжно), поэтому оставим TODO.
  // TODO: хранить соответствие (pubKey -> mark/classId/ip) во внутреннем KV/файле и удалять точечно.
  // 1) Снимем tc filters/classes
  const classId = classIdFromKey(pubKey);
  const mark = markFromKey(pubKey);
  await run('tc', ['filter', 'del', 'dev', wan, 'protocol', 'ip', 'parent', '1:', 'prio', '1',
    'handle', mark, 'fw']).catch(() => {});
  await run('tc', ['filter', 'del', 'dev', wan, 'protocol', 'ipv6', 'parent', '1:', 'prio', '1',
    'handle', mark, 'fw']).catch(() => {});
  await run('tc', ['class', 'del', 'dev', wan, 'classid', classId]).catch(() => {});
  // Для nft — аккуратного удаления без хранения состояния сейчас не делаем.
  // Рекомендация: периодический reconcile (build‑from‑DB) отдельной утилитой.
}

/* ============ HTTP API ============ */

app.get('/healthz', (_req, res) => res.send('ok'));

app.get('/info', async (_req, res) => {
  const wan = await detectWan();
  const pub = await run('sh', ['-c', `wg show ${WG_IF} public-key 2>/dev/null || true`])
    .then(r => r.stdout.trim()).catch(() => '');
  res.json({ wgInterface: WG_IF, wanInterface: wan, serverPublicKey: pub });
});

app.post('/peers/upsert', auth, async (req, res) => {
  const schema = z.object({
    pubKey: z.string().min(20),
    addressCidr: z.string().min(8), // 10.200.0.X/32
    rateMbps: z.number().int().min(1).max(100000),
    allowedIps: z.string().optional(), // опционально; обычно = addressCidr
    deviceId: z.string().optional()
  });
  const { pubKey, addressCidr, rateMbps, deviceId } = schema.parse(req.body);
  try {
    await upsertPeer(pubKey, addressCidr, rateMbps, deviceId);
    const srvPub = await run('sh', ['-c', `wg show ${WG_IF} public-key 2>/dev/null || true`])
      .then(r => r.stdout.trim()).catch(() => '');
    res.json({ ok: true, serverPublicKey: srvPub });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/peers/delete', auth, async (req, res) => {
  const schema = z.object({
    pubKey: z.string().min(20),
    addressCidr: z.string().min(8)
  });
  const { pubKey, addressCidr } = schema.parse(req.body);
  try {
    await deletePeer(pubKey, addressCidr);
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`gateway-agent listening on :${PORT} (WG_IF=${WG_IF})`);
});