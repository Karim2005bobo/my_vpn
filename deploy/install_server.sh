#!/usr/bin/env bash
# Установка сервера MiniVPN на Linux-VPS (Debian/Ubuntu/CentOS/Fedora):
#   sudo bash deploy/install_server.sh [публичный_IP_или_домен]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запустите от root: sudo bash $0"; exit 1; }
SRC=$(cd "$(dirname "$0")/.." && pwd)
PORT=${PORT:-51820}
HOST=${1:-}

echo "== зависимости"
if command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y -qq python3 python3-cryptography iproute2 iptables curl
elif command -v dnf >/dev/null; then
    dnf install -y -q python3 python3-cryptography iproute iptables curl
elif command -v yum >/dev/null; then
    yum install -y -q python3 python3-cryptography iproute iptables curl
else
    echo "Установите вручную: python3, python3-cryptography, iproute2, iptables"
fi
[ -e /dev/net/tun ] || { echo "Нет /dev/net/tun — включите TUN/TAP в панели VPS"; exit 1; }

echo "== файлы"
install -d /opt/minivpn
rm -rf /opt/minivpn/minivpn && cp -r "$SRC/minivpn" /opt/minivpn/
cat > /usr/local/bin/minivpn-server <<'SH'
#!/bin/sh
PYTHONPATH=/opt/minivpn exec python3 -m minivpn.server "$@"
SH
chmod 755 /usr/local/bin/minivpn-server

if [ ! -f /etc/minivpn/server.json ]; then
    [ -n "$HOST" ] || HOST=$(curl -4 -fs --max-time 5 https://api.ipify.org || true)
    [ -n "$HOST" ] || HOST=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
    minivpn-server init --host "$HOST" --port "$PORT"
fi

echo "== служба"
cp "$SRC/deploy/minivpn-server.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now minivpn-server
systemctl restart minivpn-server

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow "$PORT/udp"; fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$PORT/udp" && firewall-cmd -q --reload
fi

echo
systemctl --no-pager --lines=3 status minivpn-server || true
echo
echo "Готово. Сервер слушает UDP $PORT (не забудьте открыть порт в панели хостинга)."
echo "Добавить клиента:   sudo minivpn-server add-client laptop"
echo "Список клиентов:    sudo minivpn-server list"
echo "Журнал:             journalctl -u minivpn-server -f"
