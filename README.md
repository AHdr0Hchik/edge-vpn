# Edge VPN Monorepo

Сервисы:
- server: сервер предприятия (Express + TypeScript).
- gateway-agent: агент VPN-шлюза (Express + TypeScript).
- device-agent: агент устройства (Go).

Dev окружение:
- Node.js >= 20, npm >= 9
- Go >= 1.22
- Docker (для локальной БД и сборок)

Быстрый старт:
1) Установить Node 20 и Go 1.22
2) Установить зависимости и собрать:
   cd server && npm ci && npm run build
   cd ../gateway-agent && npm ci && npm run build
   cd ../device-agent && go build -o bin/device-agent
3) CI запускается автоматически при push/PR.