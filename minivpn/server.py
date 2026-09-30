"""Сервер MiniVPN (Linux): приём клиентов по UDP, TUN-интерфейс, NAT в интернет, управление клиентами.

    python -m minivpn.server init --host vpn.example.com       # ключи и конфиг
    python -m minivpn.server add-client laptop                  # выдаёт строку minivpn://...
    python -m minivpn.server run                                # запуск (root)
"""
import argparse
import ipaddress
import json
import logging
import os
import selectors
import signal
import socket
import sys
import time

from . import __version__
from .crypto import (CryptoError, ResponderHandshake, TAG_LEN, TransportKeys, generate_private_key, key_from_str,
                     key_to_str, public_key, random_index)
from .protocol import (DEAD_TIMEOUT, DEFAULT_MTU, DEFAULT_PORT, HDR_DATA, HDR_INIT, INNER_DISCONNECT, INNER_IP,
                       INNER_KEEPALIVE, KEEPALIVE_INTERVAL, MSG_DATA, MSG_INIT, SESSION_EXPIRE, encode_profile,
                       pack_resp)

log = logging.getLogger("minivpn.server")

DEFAULT_CONFIG = "/etc/minivpn/server.json"


# ---------------------------------------------------------------- конфигурация

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data, secret=True):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if secret else 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def clients_dir(config_path):
    return os.path.join(os.path.dirname(os.path.abspath(config_path)), "clients")


def allocate_ip(cfg):
    net = ipaddress.ip_network(cfg["network"])
    used = {cfg["address"]} | {c["ip"] for c in cfg["clients"]}
    for host in net.hosts():
        if str(host) not in used:
            return str(host)
    raise RuntimeError(f"в сети {net} закончились свободные адреса")


def client_profile(cfg, name, private_key):
    return {"v": 1, "name": name, "host": cfg["public_host"], "port": cfg["port"],
            "server_key": key_to_str(public_key(key_from_str(cfg["private_key"]))),
            "private_key": private_key}


# ---------------------------------------------------------------- состояние

class Peer:
    def __init__(self, name, key, ip):
        self.name, self.key, self.ip = name, key, ip
        self.ip_bytes = ipaddress.IPv4Address(ip).packed
        self.last_ts = b""
        self.current = self.previous = self.pending = None
        self.endpoint = None
        self.last_rx = 0.0
        self.handshake_at = 0.0
        self.rx = self.tx = 0

    def sessions(self):
        return [s for s in (self.current, self.previous, self.pending) if s]


class Session:
    __slots__ = ("local_index", "remote_index", "keys", "peer", "created")

    def __init__(self, local_index, remote_index, keys, peer):
        self.local_index, self.remote_index, self.keys, self.peer = local_index, remote_index, keys, peer
        self.created = time.monotonic()


class Server:
    def __init__(self, config_path):
        self.config_path = config_path
        self.cfg = load_json(config_path)
        self.private_key = key_from_str(self.cfg["private_key"])
        self.peers = {}          # статический ключ -> Peer
        self.by_ip = {}          # 4 байта IP -> Peer
        self.sessions = {}       # локальный индекс -> Session
        self._mtime = 0.0
        self._stop = False
        self._reload_requested = False
        self._last_unknown_log = 0.0
        self.reload_clients()

    # --- клиенты

    def reload_clients(self):
        try:
            self._mtime = os.path.getmtime(self.config_path)
            cfg = load_json(self.config_path)
        except (OSError, ValueError) as e:
            log.error("не удалось перечитать конфиг: %s", e)
            return
        self.cfg["clients"] = cfg.get("clients", [])
        peers, by_ip = {}, {}
        for c in self.cfg["clients"]:
            if not c.get("enabled", True):
                continue
            try:
                key = key_from_str(c["public_key"])
            except CryptoError:
                log.error("клиент %s: некорректный ключ", c.get("name"))
                continue
            old = self.peers.get(key)
            peer = old if old and old.ip == c["ip"] else Peer(c["name"], key, c["ip"])
            peer.name = c["name"]
            peers[key] = peer
            by_ip[peer.ip_bytes] = peer
        for key, peer in self.peers.items():
            if peers.get(key) is not peer:
                self._drop_peer(peer)
                log.info("клиент %s отключён (удалён из конфига)", peer.name)
        added = [p.name for k, p in peers.items() if k not in self.peers]
        self.peers, self.by_ip = peers, by_ip
        if added:
            log.info("добавлены клиенты: %s", ", ".join(added))

    def _drop_peer(self, peer):
        for s in peer.sessions():
            self.sessions.pop(s.local_index, None)
        peer.current = peer.previous = peer.pending = None
        peer.endpoint = None

    def _new_index(self):
        while True:
            i = random_index()
            if i not in self.sessions:
                return i

    # --- сеть

    def send(self, peer, kind, payload=b""):
        s = peer.current
        if not s or not peer.endpoint:
            return
        try:
            counter = s.keys.next_counter()
        except CryptoError:
            return
        hdr = HDR_DATA.pack(MSG_DATA, s.remote_index, counter)
        try:
            self.sock.sendto(hdr + s.keys.encrypt(counter, hdr, bytes((kind,)) + payload), peer.endpoint)
            peer.tx += len(payload)
        except OSError as e:
            log.debug("sendto %s: %s", peer.endpoint, e)

    def on_udp(self, data, addr):
        if not data:
            return
        if data[0] == MSG_DATA:
            self.on_data(data, addr)
        elif data[0] == MSG_INIT:
            self.on_init(data, addr)

    def on_init(self, data, addr):
        if len(data) < HDR_INIT.size + ResponderHandshake.INIT_OVERHEAD:
            return
        _, sender = HDR_INIT.unpack_from(data)
        hs = ResponderHandshake(self.private_key)
        try:
            client_key, ts = hs.read_init(data[HDR_INIT.size:])
        except CryptoError:
            return
        peer = self.peers.get(client_key)
        if peer is None:
            now = time.monotonic()
            if now - self._last_unknown_log > 10:
                self._last_unknown_log = now
                log.warning("рукопожатие от неизвестного ключа %s (%s:%s)", key_to_str(client_key), *addr[:2])
            return
        if len(ts) != 12 or ts <= peer.last_ts:
            log.warning("%s: повтор старого рукопожатия отклонён", peer.name)
            return
        peer.last_ts = ts
        net = ipaddress.ip_network(self.cfg["network"])
        conf = {"ip": peer.ip, "prefix": net.prefixlen, "gateway": self.cfg["address"],
                "dns": self.cfg.get("dns", []), "mtu": self.cfg.get("mtu", DEFAULT_MTU),
                "keepalive": KEEPALIVE_INTERVAL}
        msg, send_key, recv_key = hs.write_response(json.dumps(conf).encode())
        sess = Session(self._new_index(), sender, TransportKeys(send_key, recv_key), peer)
        if peer.pending:
            self.sessions.pop(peer.pending.local_index, None)
        peer.pending = sess
        self.sessions[sess.local_index] = sess
        try:
            self.sock.sendto(pack_resp(sess.local_index, sender, msg), addr)
        except OSError as e:
            log.debug("sendto %s: %s", addr, e)

    def on_data(self, data, addr):
        if len(data) < HDR_DATA.size + TAG_LEN:
            return
        _, idx, counter = HDR_DATA.unpack_from(data)
        sess = self.sessions.get(idx)
        if sess is None:
            return
        try:
            inner = sess.keys.decrypt(counter, data[:HDR_DATA.size], data[HDR_DATA.size:])
        except CryptoError:
            return
        peer = sess.peer
        now = time.monotonic()
        if sess is peer.pending:
            first = peer.current is None
            if peer.previous:
                self.sessions.pop(peer.previous.local_index, None)
            peer.previous, peer.current, peer.pending = peer.current, sess, None
            peer.handshake_at = now
            if first:
                log.info("%s подключился с %s:%s, адрес %s", peer.name, addr[0], addr[1], peer.ip)
        if sess is peer.current and peer.endpoint != addr:
            peer.endpoint = addr
        peer.last_rx = now
        if not inner:
            return
        kind = inner[0]
        if kind == INNER_IP:
            pkt = inner[1:]
            peer.rx += len(pkt)
            # клиент может отправлять только от своего адреса — защита от подмены
            if len(pkt) >= 20 and pkt[0] >> 4 == 4 and pkt[12:16] == peer.ip_bytes:
                self.tun.write(pkt)
        elif kind == INNER_KEEPALIVE:
            self.send(peer, INNER_KEEPALIVE)
        elif kind == INNER_DISCONNECT:
            log.info("%s отключился", peer.name)
            self._drop_peer(peer)

    def on_tun(self, pkt):
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            return
        peer = self.by_ip.get(pkt[16:20])
        if peer:
            self.send(peer, INNER_IP, pkt)

    # --- обслуживание

    def tick(self):
        now = time.monotonic()
        for idx, s in list(self.sessions.items()):
            if now - s.created > SESSION_EXPIRE:
                peer = s.peer
                self.sessions.pop(idx, None)
                if s is peer.current:
                    peer.current, peer.endpoint = None, None
                    log.info("%s: сессия истекла", peer.name)
                elif s is peer.previous:
                    peer.previous = None
                elif s is peer.pending:
                    peer.pending = None
        if self._reload_requested:
            self._reload_requested = False
            self.reload_clients()
        else:
            try:
                if os.path.getmtime(self.config_path) != self._mtime:
                    self.reload_clients()
            except OSError:
                pass

    def status(self):
        now = time.monotonic()
        peers = []
        for p in self.peers.values():
            online = p.current is not None and now - p.last_rx < DEAD_TIMEOUT
            peers.append({"name": p.name, "ip": p.ip, "online": online,
                          "endpoint": f"{p.endpoint[0]}:{p.endpoint[1]}" if p.endpoint else None,
                          "last_seen_sec": round(now - p.last_rx) if p.last_rx else None,
                          "rx_bytes": p.rx, "tx_bytes": p.tx})
        return {"time": int(time.time()), "listen": f"{self.cfg.get('listen', '0.0.0.0')}:{self.cfg['port']}",
                "network": self.cfg["network"], "peers": peers}

    def write_status(self):
        try:
            save_json(os.path.join(os.path.dirname(os.path.abspath(self.config_path)), "status.json"),
                      self.status(), secret=False)
        except OSError as e:
            log.debug("status.json: %s", e)

    def run(self):
        from .netconfig import ServerNetwork
        from .tun import open_tun
        cfg = self.cfg
        listen = cfg.get("listen", "0.0.0.0")
        family = socket.AF_INET6 if ":" in listen else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.sock.bind((listen, int(cfg["port"])))
        self.sock.setblocking(False)
        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, opt, 4 * 1024 * 1024)
            except OSError:
                pass
        self.tun = open_tun(cfg.get("tun", "minivpn0"))
        net = ServerNetwork(self.tun.name, cfg["address"], cfg["network"], cfg.get("mtu", DEFAULT_MTU),
                            wan=cfg.get("wan"), nat=cfg.get("nat", True))
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "_stop", True))
        signal.signal(signal.SIGHUP, lambda *_: setattr(self, "_reload_requested", True))
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ, "udp")
        sel.register(self.tun.fileno(), selectors.EVENT_READ, "tun")
        try:
            net.up()
            log.info("MiniVPN %s: слушаю udp %s:%s, интерфейс %s (%s), клиентов: %d",
                     __version__, listen, cfg["port"], self.tun.name, cfg["address"], len(self.peers))
            next_tick = next_status = 0.0
            while not self._stop:
                for key, _ in sel.select(timeout=1.0):
                    if key.data == "udp":
                        for _ in range(256):
                            try:
                                data, addr = self.sock.recvfrom(65535)
                            except (BlockingIOError, InterruptedError):
                                break
                            except OSError as e:
                                log.debug("recvfrom: %s", e)
                                break
                            self.on_udp(data, addr)
                    else:
                        for _ in range(256):
                            pkt = self.tun.read()
                            if not pkt:
                                break
                            self.on_tun(pkt)
                now = time.monotonic()
                if now >= next_tick:
                    next_tick = now + 1
                    self.tick()
                if now >= next_status:
                    next_status = now + 5
                    self.write_status()
        finally:
            log.info("остановка сервера")
            for peer in list(self.peers.values()):
                self._drop_peer(peer)
            net.down()
            sel.close()
            self.tun.close()
            self.sock.close()


# ---------------------------------------------------------------- CLI

def cmd_init(args):
    if os.path.exists(args.config) and not args.force:
        sys.exit(f"{args.config} уже существует (используйте --force для перезаписи)")
    net = ipaddress.ip_network(args.network)
    os.makedirs(os.path.dirname(os.path.abspath(args.config)), mode=0o700, exist_ok=True)
    cfg = {"public_host": args.host, "listen": args.listen, "port": args.port,
           "private_key": key_to_str(generate_private_key()), "network": str(net),
           "address": str(next(net.hosts())), "dns": args.dns, "mtu": args.mtu, "tun": args.tun,
           "nat": True, "wan": None, "clients": []}
    save_json(args.config, cfg)
    print(f"Конфиг сервера создан: {args.config}")
    print(f"Публичный ключ сервера: {key_to_str(public_key(key_from_str(cfg['private_key'])))}")
    print(f"Откройте UDP-порт {args.port} на файрволе и добавьте клиента: add-client <имя>")


def cmd_add(args):
    cfg = load_json(args.config)
    if any(c["name"] == args.name for c in cfg["clients"]):
        sys.exit(f"клиент {args.name} уже есть")
    ip = args.ip or allocate_ip(cfg)
    if ipaddress.ip_address(ip) not in ipaddress.ip_network(cfg["network"]) or ip == cfg["address"] or \
            any(c["ip"] == ip for c in cfg["clients"]):
        sys.exit(f"адрес {ip} недоступен")
    priv = key_to_str(generate_private_key())
    cfg["clients"].append({"name": args.name, "public_key": key_to_str(public_key(key_from_str(priv))),
                           "ip": ip, "enabled": True, "created": time.strftime("%Y-%m-%d %H:%M:%S")})
    save_json(args.config, cfg)
    uri = encode_profile(client_profile(cfg, args.name, priv))
    d = clients_dir(args.config)
    os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(d, f"{args.name}.mvpn")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(uri + "\n")
    print(f"Клиент {args.name} добавлен, адрес в VPN: {ip}")
    print(f"Файл профиля: {path}")
    print("Строка подключения (вставьте в клиент MiniVPN, держите в секрете):\n")
    print(uri)


def cmd_remove(args):
    cfg = load_json(args.config)
    before = len(cfg["clients"])
    cfg["clients"] = [c for c in cfg["clients"] if c["name"] != args.name]
    if len(cfg["clients"]) == before:
        sys.exit(f"клиент {args.name} не найден")
    save_json(args.config, cfg)
    try:
        os.remove(os.path.join(clients_dir(args.config), f"{args.name}.mvpn"))
    except FileNotFoundError:
        pass
    print(f"Клиент {args.name} удалён (работающий сервер отключит его в течение секунды)")


def cmd_enable(args, enabled):
    cfg = load_json(args.config)
    for c in cfg["clients"]:
        if c["name"] == args.name:
            c["enabled"] = enabled
            save_json(args.config, cfg)
            print(f"Клиент {args.name} {'включён' if enabled else 'заблокирован'}")
            return
    sys.exit(f"клиент {args.name} не найден")


def cmd_show(args):
    path = os.path.join(clients_dir(args.config), f"{args.name}.mvpn")
    try:
        with open(path) as f:
            print(f.read().strip())
    except FileNotFoundError:
        sys.exit(f"профиль {path} не найден")


def fmt_bytes(n):
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def cmd_list(args):
    cfg = load_json(args.config)
    status = {}
    try:
        st = load_json(os.path.join(os.path.dirname(os.path.abspath(args.config)), "status.json"))
        if time.time() - st["time"] < 30:
            status = {p["name"]: p for p in st["peers"]}
    except (OSError, ValueError, KeyError):
        pass
    print(f"Сервер {cfg['public_host']}:{cfg['port']}, сеть {cfg['network']}, "
          f"ключ {key_to_str(public_key(key_from_str(cfg['private_key'])))}")
    if not cfg["clients"]:
        print("Клиентов нет. Добавьте: add-client <имя>")
        return
    print(f"{'ИМЯ':<20}{'АДРЕС':<16}{'СОСТОЯНИЕ':<14}{'ОТКУДА':<24}{'ПРИНЯТО':>10}{'ОТПРАВЛЕНО':>12}")
    for c in cfg["clients"]:
        st = status.get(c["name"], {})
        state = "заблокирован" if not c.get("enabled", True) else ("онлайн" if st.get("online") else "офлайн")
        print(f"{c['name']:<20}{c['ip']:<16}{state:<14}{st.get('endpoint') or '-':<24}"
              f"{fmt_bytes(st.get('rx_bytes', 0)):>10}{fmt_bytes(st.get('tx_bytes', 0)):>12}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="minivpn-server", description="Сервер MiniVPN")
    ap.add_argument("-c", "--config", default=os.environ.get("MINIVPN_SERVER_CONFIG", DEFAULT_CONFIG))
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="создать ключи и конфиг сервера")
    p.add_argument("--host", required=True, help="публичный IP или домен сервера (попадёт в профили клиентов)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--network", default="10.8.0.0/24", help="адреса внутри VPN")
    p.add_argument("--dns", nargs="+", default=["1.1.1.1", "8.8.8.8"])
    p.add_argument("--mtu", type=int, default=DEFAULT_MTU)
    p.add_argument("--tun", default="minivpn0")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("add-client", help="добавить клиента и выдать строку подключения")
    p.add_argument("name")
    p.add_argument("--ip", help="фиксированный адрес в VPN (по умолчанию — первый свободный)")
    for name, hlp in (("remove-client", "удалить клиента"), ("disable-client", "заблокировать клиента"),
                      ("enable-client", "разблокировать клиента"), ("show-client", "показать строку подключения")):
        sub.add_parser(name, help=hlp).add_argument("name")
    sub.add_parser("list", help="клиенты и их состояние")
    sub.add_parser("run", help="запустить сервер (нужен root)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.cmd == "init":
        cmd_init(args)
    elif args.cmd == "add-client":
        cmd_add(args)
    elif args.cmd == "remove-client":
        cmd_remove(args)
    elif args.cmd in ("enable-client", "disable-client"):
        cmd_enable(args, args.cmd == "enable-client")
    elif args.cmd == "show-client":
        cmd_show(args)
    elif args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "run":
        if os.geteuid() != 0:
            sys.exit("сервер нужно запускать от root (TUN-интерфейс и iptables)")
        Server(args.config).run()


if __name__ == "__main__":
    main()
