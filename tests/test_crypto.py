import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from minivpn.crypto import (CryptoError, InitiatorHandshake, ReplayWindow, ResponderHandshake,  # noqa: E402
                            TransportKeys, generate_private_key, key_from_str, key_to_str, public_key)
from minivpn.protocol import decode_profile, encode_profile, timestamp  # noqa: E402


def handshake(client_priv, server_priv, server_pub_known):
    ini = InitiatorHandshake(client_priv, server_pub_known)
    msg1 = ini.write_init(b"hello")
    res = ResponderHandshake(server_priv)
    rs, payload = res.read_init(msg1)
    msg2, s_send, s_recv = res.write_response(b"config")
    payload2, c_send, c_recv = ini.read_response(msg2)
    return rs, payload, payload2, (c_send, c_recv), (s_send, s_recv)


class HandshakeTest(unittest.TestCase):
    def setUp(self):
        self.c = generate_private_key()
        self.s = generate_private_key()

    def test_roundtrip(self):
        rs, p1, p2, ck, sk = handshake(self.c, self.s, public_key(self.s))
        self.assertEqual(rs, public_key(self.c))
        self.assertEqual((p1, p2), (b"hello", b"config"))
        self.assertEqual(ck, (sk[1], sk[0]))  # отправка клиента = приём сервера
        self.assertNotEqual(ck[0], ck[1])

    def test_wrong_server_key(self):
        other = generate_private_key()
        with self.assertRaises(CryptoError):
            handshake(self.c, self.s, public_key(other))

    def test_tampered_init(self):
        ini = InitiatorHandshake(self.c, public_key(self.s))
        msg = bytearray(ini.write_init(b"x"))
        msg[40] ^= 1
        with self.assertRaises(CryptoError):
            ResponderHandshake(self.s).read_init(bytes(msg))

    def test_fresh_keys_each_time(self):
        a = handshake(self.c, self.s, public_key(self.s))[3]
        b = handshake(self.c, self.s, public_key(self.s))[3]
        self.assertNotEqual(a, b)

    def test_transport(self):
        _, _, _, (cs, cr), (ss, sr) = handshake(self.c, self.s, public_key(self.s))
        client, server = TransportKeys(cs, cr), TransportKeys(ss, sr)
        n = client.next_counter()
        ct = client.encrypt(n, b"hdr", b"packet")
        self.assertEqual(server.decrypt(n, b"hdr", ct), b"packet")
        with self.assertRaises(CryptoError):  # повтор
            server.decrypt(n, b"hdr", ct)
        n2 = client.next_counter()
        with self.assertRaises(CryptoError):  # чужой заголовок
            server.decrypt(n2, b"HDR", client.encrypt(n2, b"hdr", b"x"))


class ReplayWindowTest(unittest.TestCase):
    def test_window(self):
        w = ReplayWindow()
        for n in (0, 5, 3, 4000, 3999):
            self.assertTrue(w.check(n))
            w.update(n)
        for n in (0, 5, 3, 4000, 3999, 10):
            self.assertFalse(w.check(n), n)
        self.assertTrue(w.check(3000))
        self.assertTrue(w.check(4001))


class ProfileTest(unittest.TestCase):
    def test_uri(self):
        k = key_to_str(generate_private_key())
        prof = {"name": "ноутбук", "host": "vpn.example.com", "port": 51820, "server_key": k, "private_key": k}
        self.assertEqual(decode_profile(encode_profile(prof)), prof)
        self.assertEqual(key_from_str(k), key_from_str(k + "\n"))

    def test_timestamp_monotonic(self):
        self.assertLess(timestamp(), timestamp())


if __name__ == "__main__":
    unittest.main()
