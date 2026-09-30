"""Настройка адресов, маршрутов, DNS и NAT через системные утилиты (ip/iptables, netsh/route)."""
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys

log = logging.getLogger("minivpn.net")


def run(cmd, check=True):
    log.debug("$ %s", " ".join(cmd))
    kw = {}
    if sys.platform == "win32":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and res.returncode != 0:
        raise RuntimeError(f"команда {' '.join(cmd)} завершилась с ошибкой: {(res.stderr or res.stdout).strip()}")
    return res


def is_admin():
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------- сервер (Linux)

def default_interface():
    out = run(["ip", "-4", "route", "show", "default"], check=False).stdout
    m = re.search(r"\bdev (\S+)", out)
    return m.group(1) if m else None


class ServerNetwork:
    """Адрес на TUN, форвардинг и NAT (MASQUERADE) в интернет через внешний интерфейс."""

    def __init__(self, tun_name, address, network, mtu, wan=None, nat=True):
        self.tun, self.address, self.network, self.mtu = tun_name, address, network, mtu
        self.wan = wan or default_interface()
        self.nat = nat
        self._rules = []
        self._old_forward = None

    def up(self):
        prefix = ipaddress.ip_network(self.network).prefixlen
        run(["ip", "addr", "replace", f"{self.address}/{prefix}", "dev", self.tun])
        run(["ip", "link", "set", "dev", self.tun, "mtu", str(self.mtu), "up"])
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            self._old_forward = f.read().strip()
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        if not self.nat:
            return
        if not self.wan:
            log.warning("не найден интерфейс с маршрутом по умолчанию — NAT не настроен")
            return
        rules = [
            ["-t", "nat", "POSTROUTING", "-s", self.network, "-o", self.wan, "-j", "MASQUERADE"],
            ["FORWARD", "-i", self.tun, "-j", "ACCEPT"],
            ["FORWARD", "-o", self.tun, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            # MSS clamping: TCP-сегменты подгоняются под MTU туннеля, иначе «зависают» некоторые сайты
            ["-t", "mangle", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        ]
        for rule in rules:
            table, chain, spec = (rule[:2], rule[2], rule[3:]) if rule[0] == "-t" else ([], rule[0], rule[1:])
            if run(["iptables", *table, "-C", chain, *spec], check=False).returncode != 0:
                run(["iptables", *table, "-I", chain, "1", *spec])
                self._rules.append((table, chain, spec))
        log.info("NAT: %s -> %s", self.network, self.wan)

    def down(self):
        for table, chain, spec in reversed(self._rules):
            run(["iptables", *table, "-D", chain, *spec], check=False)
        self._rules = []
        if self._old_forward is not None and self._old_forward != "1":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(self._old_forward)


# ---------------------------------------------------------------- клиент

def client_network(tun_name, cfg, server_ip, full_tunnel=True, set_dns=True):
    if sys.platform == "win32":
        return WindowsClientNetwork(tun_name, cfg, server_ip, full_tunnel, set_dns)
    return LinuxClientNetwork(tun_name, cfg, server_ip, full_tunnel, set_dns)


class LinuxClientNetwork:
    RESOLV = "/etc/resolv.conf"
    RESOLV_BACKUP = "/etc/resolv.conf.minivpn-backup"

    def __init__(self, tun, cfg, server_ip, full_tunnel, set_dns):
        self.tun, self.cfg, self.server_ip = tun, cfg, server_ip
        self.full_tunnel, self.set_dns = full_tunnel, set_dns
        self._host_route = None
        self._v6_routes = []
        self._dns_mode = None
        self._resolv_link = None

    def up(self):
        cfg = self.cfg
        run(["ip", "addr", "replace", f"{cfg['ip']}/{cfg['prefix']}", "dev", self.tun])
        run(["ip", "link", "set", "dev", self.tun, "mtu", str(cfg["mtu"]), "up"])
        if self.full_tunnel:
            out = run(["ip", "-4", "route", "get", self.server_ip]).stdout
            via = re.search(r"\bvia (\S+)", out)
            dev = re.search(r"\bdev (\S+)", out)
            if dev and dev.group(1) != self.tun:
                self._host_route = [f"{self.server_ip}/32"] + (["via", via.group(1)] if via else []) + \
                                   ["dev", dev.group(1)]
                run(["ip", "route", "replace", *self._host_route])
            for net in ("0.0.0.0/1", "128.0.0.0/1"):
                run(["ip", "route", "replace", net, "dev", self.tun])
            # туннель только IPv4: глушим глобальный IPv6, чтобы трафик не утекал мимо VPN
            for net in ("::/1", "8000::/1"):
                if run(["ip", "-6", "route", "replace", "unreachable", net], check=False).returncode == 0:
                    self._v6_routes.append(net)
        if self.set_dns and cfg.get("dns"):
            self._dns_up(cfg["dns"])

    def _dns_up(self, servers):
        if shutil.which("resolvectl") and run(["resolvectl", "status"], check=False).returncode == 0:
            run(["resolvectl", "dns", self.tun, *servers])
            run(["resolvectl", "domain", self.tun, "~."], check=False)
            run(["resolvectl", "default-route", self.tun, "true"], check=False)
            self._dns_mode = "resolved"
            return
        if os.path.islink(self.RESOLV):
            self._resolv_link = os.readlink(self.RESOLV)
            os.unlink(self.RESOLV)
        elif os.path.exists(self.RESOLV):
            shutil.copy2(self.RESOLV, self.RESOLV_BACKUP)
        with open(self.RESOLV, "w") as f:
            f.write("# MiniVPN\n" + "".join(f"nameserver {s}\n" for s in servers))
        self._dns_mode = "file"

    def down(self):
        if self._dns_mode == "resolved":
            run(["resolvectl", "revert", self.tun], check=False)
        elif self._dns_mode == "file":
            try:
                if self._resolv_link is not None:
                    os.unlink(self.RESOLV)
                    os.symlink(self._resolv_link, self.RESOLV)
                elif os.path.exists(self.RESOLV_BACKUP):
                    shutil.move(self.RESOLV_BACKUP, self.RESOLV)
            except OSError as e:
                log.error("не удалось восстановить %s: %s", self.RESOLV, e)
        self._dns_mode = None
        for net in self._v6_routes:
            run(["ip", "-6", "route", "del", "unreachable", net], check=False)
        self._v6_routes = []
        if self._host_route:
            run(["ip", "route", "del", *self._host_route], check=False)
            self._host_route = None


class WindowsClientNetwork:
    def __init__(self, tun, cfg, server_ip, full_tunnel, set_dns):
        self.tun, self.cfg, self.server_ip = tun, cfg, server_ip
        self.full_tunnel, self.set_dns = full_tunnel, set_dns
        self._host_route = False

    def up(self):
        cfg, name = self.cfg, self.tun
        mask = str(ipaddress.ip_network(f"0.0.0.0/{cfg['prefix']}").netmask)
        run(["netsh", "interface", "ipv4", "set", "address", f"name={name}", "source=static",
             f"address={cfg['ip']}", f"mask={mask}"])
        run(["netsh", "interface", "ipv4", "set", "subinterface", name, f"mtu={cfg['mtu']}", "store=active"],
            check=False)
        run(["netsh", "interface", "ipv4", "set", "interface", name, "metric=1"], check=False)
        if self.full_tunnel:
            gw = self._default_gateway()
            if gw:
                run(["route", "add", self.server_ip, "mask", "255.255.255.255", gw, "metric", "1"])
                self._host_route = True
            for net in ("0.0.0.0/1", "128.0.0.0/1"):
                run(["netsh", "interface", "ipv4", "add", "route", net, name, cfg["gateway"],
                     "metric=1", "store=active"])
        if self.set_dns and cfg.get("dns"):
            run(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "source=static",
                 f"address={cfg['dns'][0]}", "register=none", "validate=no"])
            for i, s in enumerate(cfg["dns"][1:], start=2):
                run(["netsh", "interface", "ipv4", "add", "dnsservers", f"name={name}", f"address={s}",
                     f"index={i}", "validate=no"], check=False)

    def _default_gateway(self):
        ps = ("Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | "
              "Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop")
        out = run(["powershell", "-NoProfile", "-Command", ps], check=False).stdout.strip()
        return out if out and out != "0.0.0.0" else None

    def down(self):
        if self._host_route:
            run(["route", "delete", self.server_ip], check=False)
            self._host_route = False
