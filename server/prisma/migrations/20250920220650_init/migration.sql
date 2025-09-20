-- CreateEnum
CREATE TYPE "SubscriptionStatus" AS ENUM ('ACTIVE', 'PAST_DUE', 'CANCELLED');

-- CreateEnum
CREATE TYPE "PaymentStatus" AS ENUM ('SUCCEEDED', 'PENDING', 'FAILED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL,
    "name" TEXT,
    "ownerId" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "publicKey" TEXT,
    "vpnEnabled" BOOLEAN NOT NULL DEFAULT true,
    "lastSeen" TIMESTAMP(3),
    "speedTierId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Device_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SpeedTier" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "rateMbps" INTEGER NOT NULL,
    "priceCents" INTEGER NOT NULL,

    CONSTRAINT "SpeedTier_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Subscription" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "speedTierId" TEXT NOT NULL,
    "status" "SubscriptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "currentPeriodEnd" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Subscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Payment" (
    "id" TEXT NOT NULL,
    "subscriptionId" TEXT NOT NULL,
    "amountCents" INTEGER NOT NULL,
    "status" "PaymentStatus" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Payment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VpnServer" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "location" TEXT,
    "endpoint" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "apiUrl" TEXT NOT NULL,
    "apiToken" TEXT NOT NULL,
    "wgInterface" TEXT NOT NULL DEFAULT 'wg0',
    "ipPoolCidr" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VpnServer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VpnPeer" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "serverId" TEXT NOT NULL,
    "addressCidr" TEXT NOT NULL,
    "rateMbps" INTEGER NOT NULL DEFAULT 40,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VpnPeer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BypassDomain" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BypassDomain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeviceHeartbeat" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "data" JSONB NOT NULL,

    CONSTRAINT "DeviceHeartbeat_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "Device_ownerId_idx" ON "Device"("ownerId");

-- CreateIndex
CREATE INDEX "Device_lastSeen_idx" ON "Device"("lastSeen");

-- CreateIndex
CREATE UNIQUE INDEX "SpeedTier_name_key" ON "SpeedTier"("name");

-- CreateIndex
CREATE INDEX "Subscription_userId_deviceId_idx" ON "Subscription"("userId", "deviceId");

-- CreateIndex
CREATE INDEX "VpnServer_enabled_idx" ON "VpnServer"("enabled");

-- CreateIndex
CREATE UNIQUE INDEX "VpnPeer_deviceId_key" ON "VpnPeer"("deviceId");

-- CreateIndex
CREATE INDEX "VpnPeer_serverId_idx" ON "VpnPeer"("serverId");

-- CreateIndex
CREATE UNIQUE INDEX "VpnPeer_serverId_addressCidr_key" ON "VpnPeer"("serverId", "addressCidr");

-- CreateIndex
CREATE INDEX "BypassDomain_deviceId_idx" ON "BypassDomain"("deviceId");

-- CreateIndex
CREATE UNIQUE INDEX "BypassDomain_deviceId_domain_key" ON "BypassDomain"("deviceId", "domain");

-- CreateIndex
CREATE INDEX "DeviceHeartbeat_deviceId_at_idx" ON "DeviceHeartbeat"("deviceId", "at");

-- AddForeignKey
ALTER TABLE "Device" ADD CONSTRAINT "Device_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Device" ADD CONSTRAINT "Device_speedTierId_fkey" FOREIGN KEY ("speedTierId") REFERENCES "SpeedTier"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_speedTierId_fkey" FOREIGN KEY ("speedTierId") REFERENCES "SpeedTier"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_subscriptionId_fkey" FOREIGN KEY ("subscriptionId") REFERENCES "Subscription"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VpnPeer" ADD CONSTRAINT "VpnPeer_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VpnPeer" ADD CONSTRAINT "VpnPeer_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "VpnServer"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BypassDomain" ADD CONSTRAINT "BypassDomain_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceHeartbeat" ADD CONSTRAINT "DeviceHeartbeat_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
