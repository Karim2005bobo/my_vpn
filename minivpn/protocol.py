"""Формат пакетов по UDP и строка подключения клиента.

    INIT  : type=1 | 3 резерв | sender u32 | noise msg1 (e, enc(s), enc(timestamp))
    RESP  : type=2 | 3 резерв | sender u32 | receiver u32 | noise msg2 (e, enc(config))
    DATA  : type=3 | 3 резерв | receiver u32 | counter u64 | AEAD(inner), AAD = заголовок

inner = 1 байт вида + данные: IP-пакет, keepalive (сервер отвечает эхом) или отключение.
"""
import base64
import json
import struct
import time

MSG_INIT = 1
MSG_RESP = 2
MSG_DATA = 3

INNER_IP = 1
INNER_KEEPALIVE = 2
INNER_DISCONNECT = 3

HDR_INIT = struct.Struct("<B3xI")
HDR_RESP = struct.Struct("<B3xII")
HDR_DATA = struct.Struct("<B3xIQ")

DEFAULT_PORT = 51820
DEFAULT_MTU = 1400
KEEPALIVE_INTERVAL = 15       # клиент шлёт keepalive, если молчал столько секунд
DEAD_TIMEOUT = 45             # нет ни одного пакета от сервера → переподключение
REKEY_AFTER = 600             # новое рукопожатие (свежие ключи) каждые 10 минут
SESSION_EXPIRE = REKEY_AFTER * 3
HANDSHAKE_RETRY = 3           # повтор INIT, если нет ответа

URI_SCHEME = "minivpn://"


def timestamp():
    """12 байт, строго возрастающая метка — защита от повтора INIT."""
    ns = time.time_ns()
    return struct.pack(">QI", ns // 1_000_000_000, ns % 1_000_000_000)


def pack_init(sender, noise_msg):
    return HDR_INIT.pack(MSG_INIT, sender) + noise_msg


def pack_resp(sender, receiver, noise_msg):
    return HDR_RESP.pack(MSG_RESP, sender, receiver) + noise_msg


def encode_profile(profile):
    raw = json.dumps(profile, separators=(",", ":"), ensure_ascii=False).encode()
    return URI_SCHEME + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_profile(text):
    text = text.strip()
    if text.startswith("{"):
        data = json.loads(text)
    else:
        if not text.startswith(URI_SCHEME):
            raise ValueError("строка подключения должна начинаться с minivpn://")
        body = text[len(URI_SCHEME):]
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    for field in ("host", "port", "server_key", "private_key"):
        if field not in data:
            raise ValueError(f"в профиле нет поля {field}")
    data.setdefault("name", data["host"])
    data["port"] = int(data["port"])
    return data
