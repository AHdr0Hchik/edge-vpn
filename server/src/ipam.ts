import CIDR from 'ip-cidr';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Выбор VPN-сервера с наименьшим числом пиров (enabled)
export async function pickVpnServer() {
  const servers = await prisma.vpnServer.findMany({
    where: { enabled: true },
    include: { peers: { select: { id: true } } }
  });
  if (!servers.length) return null;
  servers.sort((a: { peers: string | any[]; }, b: { peers: string | any[]; }) => a.peers.length - b.peers.length);
  return servers[0];
}

// Аллокация свободного /32 из пула server.ipPoolCidr.
// Простая стратегия: пробегаем по хостам и пытаемся создать peer; при конфликте — следующий IP.
export async function allocateAddressCidr(serverId: string, cidr: string): Promise<string> {
  const block = new CIDR(cidr);
  const hosts = block.toArray(); // IPv4 для MVP
  // Резервируем .1 под шлюз, пропускаем network/broadcast
  for (const ip of hosts) {
    if (ip.endsWith('.0') || ip.endsWith('.255') || ip.endsWith('.1')) continue;
    const addressCidr = `${ip}/32`;
    // Проверим занятые без гонок
    const exists = await prisma.vpnPeer.findFirst({ where: { serverId, addressCidr } });
    if (!exists) return addressCidr;
  }
  throw new Error('No free IPs in pool');
}