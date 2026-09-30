"""Клиент MiniVPN: рукопожатие, TUN, маршруты, keepalive, смена ключей и автопереподключение.

    python -m minivpn.client connect minivpn://...        # или путь к .mvpn, или имя профиля
"""
import argparse
import json
import logging
import signal
import socket
import sys
import threading
import time

from .crypto import CryptoError, InitiatorHandshake, TAG_LEN, TransportKeys, key_from_str, random_index
from .protocol import (DEAD_TIMEOUT, HANDSHAKE_RETRY, HDR_DATA, HDR_RESP, INNER_DISCONNECT, INNER_IP,
                       INNER_KEEPALIVE, KEEPALIVE_INTERVAL, MSG_DATA, MSG_RESP, REKEY_AFTER, decode_profile,
                       pack_init, timestamp)

log = logging.getLogger("minivpn.client")

CONNECT_TIMEOUT = 20
PROBE_INTERVAL = 5

DISCONNECTED = "disconnected"
CONNECTING = "connecting"
CONNECTED = "connected"
RECONNECTING = "reconnecting"
DISCONNECTING = "disconnecting"
ERROR = "error"


class _Session:
    __slots__ = ("local_index", "remote_index", "keys", "created")

    def __init__(self, local_index, remote_index, keys):
        self.local_index, self.remote_index, self.keys = local_index, remote_index, keys
        self.created = time.monotonic()


class VPNClient:
    def __init__(self, profile, full_tunnel=True, set_dns=True, on_state=None):
        self.profile = profile
        self.full_tunnel = full_tunnel
        self.set_dns = set_dns
        self.on_state = on_state
        self.private_key = key_from_str(profile["private_key"])
        self.server_key = key_from_str(profile["server_key"])
        self.state = DISCONNECTED
        self.error = None
        self.config = None
        self.server_ip = None
        self.tun_name = None
        self.rx = self.tx = 0
        self.connected_since = None
        self.last_handshake = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._current = self._previous = None
        self._hs = None
        self._last_rx = self._last_tx = self._last_ka = 0.0
        self._thread = None
        self.sock = self.tun = self.net = None

    # --- управление

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="minivpn", daemon=True)
        self._thread.start()

    def stop(self, wait=True):
        self._stop.set()
        if wait and self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=15)

    def wait(self):
        while self._thread and self._thread.is_alive():
            self._thread.join(0.5)

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def _set_state(self, state, error=None):
        self.state, self.error = state, error
        if self.on_state:
            try:
                self.on_state(state, error)
            except Exception:
                log.exception("on_state")

    # --- основной поток

    def _run(self):
        workers = []
        try:
            self._set_state(CONNECTING)
            host, port = self.profile["host"], int(self.profile["port"])
            log.info("подключение к %s:%s", host, port)
            try:
                self.server_ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
            except socket.gaierror as e:
                raise ConnectionError(f"не удалось найти сервер {host}: {e}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect((self.server_ip, port))
            self.config = self._initial_handshake()
            if self.config is None:
                return
            log.info("рукопожатие выполнено, адрес в VPN %s/%s", self.config["ip"], self.config["prefix"])

            from .netconfig import client_network
            from .tun import open_tun
            self.tun = open_tun("MiniVPN" if sys.platform == "win32" else "minivpn%d")
            self.tun_name = self.tun.name
            self.net = client_network(self.tun.name, self.config, self.server_ip, self.full_tunnel, self.set_dns)
            self.net.up()
            log.info("интерфейс %s поднят%s", self.tun.name,
                     ", весь трафик идёт через VPN" if self.full_tunnel else " (только сеть VPN)")
            self.sock.settimeout(0.5)
            for target in (self._udp_loop, self._tun_loop):
                t = threading.Thread(target=target, daemon=True)
                t.start()
                workers.append(t)
            self.connected_since = time.time()
            self._set_state(CONNECTED)
            self._timer_loop()
        except Exception as e:
            log.error("%s", e)
            log.debug("подробности", exc_info=True)
            self.error = str(e)
        finally:
            self._stop.set()
            if self.state != ERROR and self.error is None:
                self._set_state(DISCONNECTING)
            for t in workers:
                t.join(timeout=3)
            self._cleanup()
            self.connected_since = None
            if self.error:
                self._set_state(ERROR, self.error)
            else:
                self._set_state(DISCONNECTED)
            log.info("отключено")

    def _cleanup(self):
        if self._current and self.sock:
            self._send(INNER_DISCONNECT)
        if self.net:
            try:
                self.net.down()
            except Exception as e:
                log.error("восстановление сети: %s", e)
            self.net = None
        if self.tun:
            self.tun.close()
            self.tun = None
        if self.sock:
            self.sock.close()
            self.sock = None
        self._current = self._previous = self._hs = None

    def _initial_handshake(self):
        deadline = time.monotonic() + CONNECT_TIMEOUT
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            if time.monotonic() > deadline:
                raise ConnectionError(f"сервер {self.profile['host']}:{self.profile['port']} не отвечает "
                                      "(проверьте адрес, открыт ли UDP-порт и активен ли ключ клиента)")
            self._send_init()
            sent = time.monotonic()
            while not self._stop.is_set() and time.monotonic() - sent < HANDSHAKE_RETRY:
                try:
                    data = self.sock.recv(65535)
                except socket.timeout:
                    continue
                except OSError:  # ICMP «порт недоступен» и т.п. — ждём и пробуем снова
                    time.sleep(0.5)
                    continue
                if data and data[0] == MSG_RESP:
                    cfg = self._on_resp(data)
                    if cfg:
                        return cfg
        return None

    def _timer_loop(self):
        silent_logged = False
        while not self._stop.wait(0.5):
            now = time.monotonic()
            cur = self._current
            since_rx = now - self._last_rx
            # трафик уходит, а в ответ тишина дольше, чем успевает прийти эхо на пробу,
            # или молчит даже keepalive: сервер мог перезапуститься и забыть сессию
            silent = (self._last_tx - self._last_rx > 2 * PROBE_INTERVAL
                      or since_rx > KEEPALIVE_INTERVAL + 2 * HANDSHAKE_RETRY)
            with self._lock:
                hs = self._hs
            if hs and now - hs[2] > HANDSHAKE_RETRY:
                self._send_init()
            elif not hs and (cur is None or now - cur.created > REKEY_AFTER
                             or cur.keys.sent_count > 2 ** 59 or silent):
                if silent and not silent_logged:
                    log.info("нет ответа от сервера %d с — повторное рукопожатие", since_rx)
                self._send_init()
            silent_logged = silent
            if since_rx > DEAD_TIMEOUT and self.state == CONNECTED:
                log.warning("сервер не отвечает %d с — переподключение", DEAD_TIMEOUT)
                self._set_state(RECONNECTING)
                with self._lock:
                    self._current = self._previous = None
                self._send_init()
            idle = now - self._last_tx >= KEEPALIVE_INTERVAL                              # держим NAT открытым
            probe = since_rx >= PROBE_INTERVAL and self._last_tx > self._last_rx          # жив ли сервер
            if (idle or probe) and now - self._last_ka >= PROBE_INTERVAL:
                self._last_ka = now
                self._send(INNER_KEEPALIVE)

    # --- рукопожатие

    def _send_init(self):
        idx = random_index()
        hs = InitiatorHandshake(self.private_key, self.server_key)
        msg = pack_init(idx, hs.write_init(timestamp()))
        with self._lock:
            self._hs = (idx, hs, time.monotonic())
        try:
            self.sock.send(msg)
        except OSError as e:
            log.debug("send init: %s", e)

    def _on_resp(self, data):
        if len(data) < HDR_RESP.size + 32 + TAG_LEN:
            return None
        _, sender, receiver = HDR_RESP.unpack_from(data)
        with self._lock:
            if not self._hs or self._hs[0] != receiver:
                return None
            idx, hs, _ = self._hs
        try:
            payload, k_send, k_recv = hs.read_response(data[HDR_RESP.size:])
            cfg = json.loads(payload)
        except (CryptoError, ValueError) as e:
            log.warning("некорректный ответ сервера: %s", e)
            return None
        sess = _Session(idx, sender, TransportKeys(k_send, k_recv))
        with self._lock:
            self._hs = None
            self._previous, self._current = self._current, sess
        self.last_handshake = time.time()
        log.debug("новые ключи сессии (индекс %08x)", idx)
        self._last_rx = time.monotonic()
        self._send(INNER_KEEPALIVE)  # подтверждение: сервер переключается на новую сессию
        return cfg

    # --- передача данных

    def _send(self, kind, payload=b""):
        s = self._current
        if s is None or self.sock is None:
            return
        try:
            counter = s.keys.next_counter()
            hdr = HDR_DATA.pack(MSG_DATA, s.remote_index, counter)
            self.sock.send(hdr + s.keys.encrypt(counter, hdr, bytes((kind,)) + payload))
        except (OSError, CryptoError):
            return
        self._last_tx = time.monotonic()
        self.tx += len(payload)

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.2)
                continue
            if not data:
                continue
            if data[0] == MSG_DATA:
                self._on_data(data)
            elif data[0] == MSG_RESP:
                if self._on_resp(data) and self.state == RECONNECTING:
                    log.info("соединение восстановлено")
                    self._set_state(CONNECTED)

    def _on_data(self, data):
        if len(data) < HDR_DATA.size + TAG_LEN:
            return
        _, idx, counter = HDR_DATA.unpack_from(data)
        sess = next((s for s in (self._current, self._previous) if s and s.local_index == idx), None)
        if sess is None:
            return
        try:
            inner = sess.keys.decrypt(counter, data[:HDR_DATA.size], data[HDR_DATA.size:])
        except CryptoError:
            return
        self._last_rx = time.monotonic()
        if inner and inner[0] == INNER_IP:
            self.rx += len(inner) - 1
            self.tun.write(inner[1:])

    def _tun_loop(self):
        while not self._stop.is_set():
            try:
                pkt = self.tun.read(0.5)
            except OSError as e:
                if not self._stop.is_set():
                    log.error("чтение TUN: %s", e)
                    self.error = str(e)
                    self._stop.set()
                return
            if pkt and pkt[0] >> 4 == 4:
                self._send(INNER_IP, pkt)


def load_profile_arg(value):
    """Строка minivpn://, путь к файлу .mvpn или имя сохранённого профиля."""
    import os
    if value.startswith("minivpn://") or value.lstrip().startswith("{"):
        return decode_profile(value)
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as f:
            return decode_profile(f.read())
    from .profiles import ProfileStore
    for p in ProfileStore().load():
        if p["name"] == value:
            return p
    raise SystemExit(f"профиль {value} не найден")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="minivpn-client", description="Консольный клиент MiniVPN")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("connect", help="подключиться (Ctrl+C — отключиться)")
    p.add_argument("profile", help="minivpn://..., путь к .mvpn или имя профиля из GUI")
    p.add_argument("--split", action="store_true", help="не заворачивать весь трафик, только сеть VPN")
    p.add_argument("--no-dns", action="store_true", help="не менять DNS")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    from .netconfig import is_admin
    if not is_admin():
        sys.exit("нужны права администратора (Linux: sudo, Windows: «Запуск от имени администратора»)")
    client = VPNClient(load_profile_arg(args.profile), full_tunnel=not args.split, set_dns=not args.no_dns)
    client.start()
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: client.stop(wait=False))
    try:
        client.wait()
    except KeyboardInterrupt:
        client.stop()
    sys.exit(1 if client.error else 0)


if __name__ == "__main__":
    main()
