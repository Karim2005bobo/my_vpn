#!/usr/bin/env bash
# Сквозной тест в изолированных сетевых пространствах (нужен root, iproute2, iptables):
#
#   mv_cli 192.0.2.2 ── 192.0.2.1 mv_srv 198.51.100.1 ── 198.51.100.2 mv_inet
#   (клиент)               (VPN-сервер, NAT)              («интернет», маршрута в 10.8.0.0/24 не знает)
#
# «Интернет» доступен клиенту только через туннель + NAT сервера.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
WORK=$(mktemp -d)
export PYTHONPATH=$PWD

cleanup() {
    set +e
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null && wait "$CLI_PID" 2>/dev/null
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null
    [ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
    for ns in mv_cli mv_srv mv_inet; do ip netns del $ns 2>/dev/null; done
    rm -rf /etc/netns/mv_cli "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; cat "$WORK/server.log"; echo "--- client log"; cat "$WORK/client.log"; exit 1; }

for ns in mv_cli mv_srv mv_inet; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip -n $ns link set lo up; done
ip link add mv-c type veth peer name mv-s1
ip link add mv-s2 type veth peer name mv-i
ip link set mv-c netns mv_cli;  ip link set mv-s1 netns mv_srv
ip link set mv-s2 netns mv_srv; ip link set mv-i netns mv_inet
ip -n mv_cli addr add 192.0.2.2/24 dev mv-c;        ip -n mv_cli link set mv-c up
ip -n mv_srv addr add 192.0.2.1/24 dev mv-s1;       ip -n mv_srv link set mv-s1 up
ip -n mv_srv addr add 198.51.100.1/24 dev mv-s2;    ip -n mv_srv link set mv-s2 up
ip -n mv_inet addr add 198.51.100.2/24 dev mv-i;    ip -n mv_inet link set mv-i up
ip -n mv_cli route add default via 192.0.2.1
ip -n mv_srv route add default via 198.51.100.2
mkdir -p /etc/netns/mv_cli && echo "nameserver 192.0.2.53" > /etc/netns/mv_cli/resolv.conf

CONF=$WORK/server.json
$PY -m minivpn.server -c "$CONF" init --host 192.0.2.1 --dns 198.51.100.2 >/dev/null
$PY -m minivpn.server -c "$CONF" add-client laptop >/dev/null
URI=$(cat "$WORK/clients/laptop.mvpn")
echo "== профиль: ${URI:0:40}..."

ip netns exec mv_srv $PY -m minivpn.server -c "$CONF" run >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1

# без VPN «интернет» недоступен (нет обратного маршрута)
ip netns exec mv_cli ping -c1 -W1 198.51.100.2 >/dev/null 2>&1 && fail "интернет доступен без VPN"

# клиент с укороченными таймерами: смена ключей каждые 4 с, обрыв определяется за 6 с
ip netns exec mv_cli $PY -c "
import minivpn.client as c
c.REKEY_AFTER = 4; c.DEAD_TIMEOUT = 6; c.KEEPALIVE_INTERVAL = 2
c.main(['-v', 'connect', '$URI'])" >"$WORK/client.log" 2>&1 &
CLI_PID=$!
for i in $(seq 50); do grep -q "интерфейс .* поднят" "$WORK/client.log" && break; sleep 0.2; done
grep -q "поднят" "$WORK/client.log" || fail "клиент не подключился"
echo "== клиент подключён"

ip netns exec mv_cli ping -c3 -i0.2 -W2 10.8.0.1 >/dev/null || fail "ping 10.8.0.1 через туннель"
echo "OK  ping сервера внутри VPN (10.8.0.1)"
ip netns exec mv_cli ping -c3 -i0.2 -W2 198.51.100.2 >/dev/null || fail "ping интернета через VPN+NAT"
echo "OK  ping «интернета» через VPN и NAT"
grep -q "nameserver 198.51.100.2" /etc/netns/mv_cli/resolv.conf || fail "DNS не выставлен"
echo "OK  DNS переключён на DNS VPN"
ip -n mv_cli route get 198.51.100.2 | grep -q minivpn || fail "маршрут не через туннель"
echo "OK  маршрут по умолчанию через туннель"

head -c 20000000 /dev/urandom > "$WORK/blob"
(cd "$WORK" && ip netns exec mv_inet $PY -m http.server 8080 --bind 198.51.100.2 >/dev/null 2>&1) &
HTTP_PID=$!
sleep 1
START=$(date +%s.%N)
ip netns exec mv_cli $PY -c "
import urllib.request, hashlib
d = urllib.request.urlopen('http://198.51.100.2:8080/blob', timeout=60).read()
print(hashlib.sha256(d).hexdigest())" > "$WORK/got.sha" || fail "скачивание через VPN"
END=$(date +%s.%N)
[ "$(cat "$WORK/got.sha")" = "$(sha256sum "$WORK/blob" | cut -d' ' -f1)" ] || fail "файл повреждён"
echo "OK  20 МБ по HTTP через VPN, контрольная сумма совпала ($($PY -c "print(round(160/($END-$START),1))") Мбит/с)"

sleep 5
[ "$(grep -c "новые ключи сессии" "$WORK/client.log")" -ge 3 ] || fail "смена ключей не происходит"
ip netns exec mv_cli ping -c2 -i0.2 -W2 198.51.100.2 >/dev/null || fail "связь после смены ключей"
echo "OK  связь сохраняется после смены ключей (rekey)"

$PY -m minivpn.server -c "$CONF" list | grep laptop | grep -q онлайн || fail "list не показывает онлайн"
echo "OK  server list: клиент онлайн"

# перезапуск сервера: клиент должен сам восстановить связь
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null || true
ip netns exec mv_srv $PY -m minivpn.server -c "$CONF" run >>"$WORK/server.log" 2>&1 &
SRV_PID=$!
OK=
for i in $(seq 40); do
    ip netns exec mv_cli ping -c1 -W1 198.51.100.2 >/dev/null 2>&1 && { OK=1; break; }
done
[ -n "$OK" ] || fail "связь не восстановилась после перезапуска сервера"
echo "OK  автопереподключение после перезапуска сервера"

# чужой ключ отвергается
BAD=$($PY -c "
from minivpn.protocol import decode_profile, encode_profile
from minivpn.crypto import generate_private_key, key_to_str
p = decode_profile('$URI'); p['private_key'] = key_to_str(generate_private_key()); print(encode_profile(p))")
ip netns exec mv_cli $PY -c "
import minivpn.client as c, sys
c.CONNECT_TIMEOUT = 4
cl = c.VPNClient(c.decode_profile('$BAD')); cl.start(); cl.wait(); sys.exit(0 if cl.error else 1)" 2>/dev/null \
    || fail "неизвестный ключ принят"
echo "OK  клиент с неизвестным ключом не подключается"

kill "$CLI_PID"; wait "$CLI_PID" 2>/dev/null || true; CLI_PID=
ip -n mv_cli link show | grep -q minivpn && fail "интерфейс не удалён"
grep -q "nameserver 192.0.2.53" /etc/netns/mv_cli/resolv.conf || fail "DNS не восстановлен"
ip -n mv_cli route | grep -q "192.0.2.1 via" && fail "маршрут до сервера не удалён"
sleep 1
grep -q "laptop отключился" "$WORK/server.log" || fail "сервер не получил уведомление об отключении"
echo "OK  отключение: интерфейс, маршруты и DNS восстановлены, сервер уведомлён"

kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null || true; SRV_PID=
ip netns exec mv_srv iptables -t nat -S | grep -q MASQUERADE && fail "NAT-правило не удалено"
echo "OK  сервер остановлен, правила iptables убраны"
echo "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"
