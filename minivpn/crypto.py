"""Криптография: ключи X25519, рукопожатие Noise_IK_25519_ChaChaPoly_BLAKE2s, транспортные ключи.

Схема та же, что у WireGuard (без PSK и cookie):
    <- s
    ...
    -> e, es, s, ss     (клиент доказывает владение своим статическим ключом)
    <- e, ee, se        (сервер доказывает владение своим, ключи сессии с PFS)
"""
import base64
import hashlib
import hmac
import os
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
PROLOGUE = b"MiniVPN v1"
KEY_LEN = 32
TAG_LEN = 16
MAX_COUNTER = 2 ** 60


class CryptoError(Exception):
    pass


# ---------------------------------------------------------------- ключи

def generate_private_key():
    return X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def public_key(private):
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def dh(private, public):
    try:
        return X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError as e:  # точка малого порядка → нулевой общий секрет
        raise CryptoError(f"DH: {e}")


def key_to_str(key):
    return base64.b64encode(key).decode()


def key_from_str(s):
    try:
        key = base64.b64decode(s.strip(), validate=True)
    except (ValueError, TypeError) as e:
        raise CryptoError(f"некорректный ключ: {e}")
    if len(key) != KEY_LEN:
        raise CryptoError("ключ должен быть 32 байта (base64)")
    return key


# ---------------------------------------------------------------- примитивы Noise

def _hash(data):
    return hashlib.blake2s(data).digest()


def _hmac(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def _hkdf(ck, ikm, n):
    temp = _hmac(ck, ikm)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = _hmac(temp, prev + bytes([i]))
        out.append(prev)
    return out


def _nonce(n):
    return b"\x00\x00\x00\x00" + struct.pack("<Q", n)


class _SymmetricState:
    def __init__(self):
        self.h = _hash(PROTOCOL_NAME) if len(PROTOCOL_NAME) > 32 else PROTOCOL_NAME.ljust(32, b"\x00")
        self.ck = self.h
        self.k = None
        self.n = 0

    def mix_hash(self, data):
        self.h = _hash(self.h + data)

    def mix_key(self, ikm):
        self.ck, temp_k = _hkdf(self.ck, ikm, 2)
        self.k, self.n = ChaCha20Poly1305(temp_k), 0

    def encrypt_and_hash(self, plaintext):
        if self.k is None:
            ct = plaintext
        else:
            ct = self.k.encrypt(_nonce(self.n), plaintext, self.h)
            self.n += 1
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext):
        if self.k is None:
            pt = ciphertext
        else:
            try:
                pt = self.k.decrypt(_nonce(self.n), ciphertext, self.h)
            except InvalidTag:
                raise CryptoError("рукопожатие: неверная подпись")
            self.n += 1
        self.mix_hash(ciphertext)
        return pt

    def split(self):
        k1, k2 = _hkdf(self.ck, b"", 2)
        return k1, k2


class InitiatorHandshake:
    """Клиентская сторона: знает статический ключ сервера заранее."""

    def __init__(self, static_private, remote_static):
        self.s = static_private
        self.rs = remote_static
        self.e = None
        self.ss = _SymmetricState()
        self.ss.mix_hash(PROLOGUE)
        self.ss.mix_hash(remote_static)

    def write_init(self, payload):
        st = self.ss
        self.e = generate_private_key()
        e_pub = public_key(self.e)
        st.mix_hash(e_pub)
        st.mix_key(dh(self.e, self.rs))
        enc_s = st.encrypt_and_hash(public_key(self.s))
        st.mix_key(dh(self.s, self.rs))
        return e_pub + enc_s + st.encrypt_and_hash(payload)

    def read_response(self, msg):
        """Возвращает (payload, ключ_отправки, ключ_приёма)."""
        if len(msg) < KEY_LEN + TAG_LEN:
            raise CryptoError("короткий ответ рукопожатия")
        st = self.ss
        re = msg[:KEY_LEN]
        st.mix_hash(re)
        st.mix_key(dh(self.e, re))
        st.mix_key(dh(self.s, re))
        payload = st.decrypt_and_hash(msg[KEY_LEN:])
        k1, k2 = st.split()
        return payload, k1, k2


class ResponderHandshake:
    """Серверная сторона: узнаёт статический ключ клиента из первого сообщения."""

    INIT_OVERHEAD = KEY_LEN + KEY_LEN + TAG_LEN + TAG_LEN

    def __init__(self, static_private):
        self.s = static_private
        self.ss = _SymmetricState()
        self.ss.mix_hash(PROLOGUE)
        self.ss.mix_hash(public_key(static_private))
        self.re = None
        self.rs = None

    def read_init(self, msg):
        """Возвращает (статический ключ клиента, payload)."""
        if len(msg) < self.INIT_OVERHEAD:
            raise CryptoError("короткое сообщение рукопожатия")
        st = self.ss
        self.re = msg[:KEY_LEN]
        st.mix_hash(self.re)
        st.mix_key(dh(self.s, self.re))
        self.rs = st.decrypt_and_hash(msg[KEY_LEN:2 * KEY_LEN + TAG_LEN])
        st.mix_key(dh(self.s, self.rs))
        payload = st.decrypt_and_hash(msg[2 * KEY_LEN + TAG_LEN:])
        return self.rs, payload

    def write_response(self, payload):
        """Возвращает (сообщение, ключ_отправки, ключ_приёма)."""
        st = self.ss
        e = generate_private_key()
        e_pub = public_key(e)
        st.mix_hash(e_pub)
        st.mix_key(dh(e, self.re))
        st.mix_key(dh(e, self.rs))
        msg = e_pub + st.encrypt_and_hash(payload)
        k1, k2 = st.split()
        return msg, k2, k1


# ---------------------------------------------------------------- транспорт

class ReplayWindow:
    """Скользящее окно счётчиков (RFC 6479-подобное): отбрасывает повторы и слишком старые пакеты."""

    SIZE = 2048

    def __init__(self):
        self.top = -1
        self.bits = 0

    def check(self, n):
        if n > self.top:
            return True
        off = self.top - n
        return off < self.SIZE and not (self.bits >> off) & 1

    def update(self, n):
        if n > self.top:
            shift = n - self.top
            self.bits = ((self.bits << shift) | 1) & ((1 << self.SIZE) - 1) if shift < self.SIZE else 1
            self.top = n
        else:
            self.bits |= 1 << (self.top - n)


class TransportKeys:
    def __init__(self, send_key, recv_key):
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self._counter = 0
        self._lock = threading.Lock()
        self.window = ReplayWindow()

    def next_counter(self):
        with self._lock:
            n = self._counter
            if n >= MAX_COUNTER:
                raise CryptoError("исчерпан счётчик сессии")
            self._counter += 1
            return n

    def encrypt(self, counter, header, plaintext):
        return self._send.encrypt(_nonce(counter), plaintext, header)

    def decrypt(self, counter, header, ciphertext):
        if not self.window.check(counter):
            raise CryptoError("повтор пакета")
        try:
            pt = self._recv.decrypt(_nonce(counter), ciphertext, header)
        except InvalidTag:
            raise CryptoError("неверная подпись пакета")
        self.window.update(counter)
        return pt

    @property
    def sent_count(self):
        return self._counter


def random_index():
    return struct.unpack("<I", os.urandom(4))[0]
