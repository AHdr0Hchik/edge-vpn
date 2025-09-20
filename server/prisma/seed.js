import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
  const tiers = [
    { name: '40 Mbps', rateMbps: 40, priceCents: 49900 },
    { name: '60 Mbps', rateMbps: 60, priceCents: 69900 },
    { name: '80 Mbps', rateMbps: 80, priceCents: 89900 },
    { name: '100 Mbps', rateMbps: 100, priceCents: 109900 }
  ];
  for (const t of tiers) {
    await prisma.speedTier.upsert({
      where: { name: t.name },
      update: t,
      create: t
    });
  }
  // При желании можно создать тестового пользователя/устройство позже (этап 3).
  console.log('Seeded speed tiers');
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });