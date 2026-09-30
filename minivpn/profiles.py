"""Хранилище профилей клиента: ~/.config/minivpn/profiles.json (Windows: %APPDATA%\\MiniVPN)."""
import json
import os
import sys

from .protocol import decode_profile


def _real_user():
    """Если GUI перезапущен через sudo/pkexec, профили храним в домашнем каталоге исходного пользователя."""
    if sys.platform == "win32":
        return None
    import pwd
    for var in ("SUDO_UID", "PKEXEC_UID"):
        uid = os.environ.get(var)
        if uid and uid.isdigit():
            try:
                return pwd.getpwuid(int(uid))
            except KeyError:
                pass
    return None


def config_dir():
    if os.environ.get("MINIVPN_CONFIG_DIR"):
        return os.environ["MINIVPN_CONFIG_DIR"]
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "MiniVPN")
    user = _real_user()
    home = user.pw_dir if user else os.path.expanduser("~")
    return os.path.join(home, ".config", "minivpn")


class ProfileStore:
    def __init__(self, directory=None):
        self.dir = directory or config_dir()
        self.path = os.path.join(self.dir, "profiles.json")

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        return data.get("profiles", [])

    def save(self, profiles, settings=None):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        data = {"profiles": profiles, "settings": settings if settings is not None else self.settings()}
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)
        user = _real_user()
        if user:  # файлы, созданные от root, возвращаем владельцу
            for p in (self.dir, self.path):
                try:
                    os.chown(p, user.pw_uid, user.pw_gid)
                except OSError:
                    pass

    def settings(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f).get("settings", {})
        except (OSError, ValueError):
            return {}

    def add(self, text):
        profile = decode_profile(text)
        profiles = self.load()
        names = {p["name"] for p in profiles}
        base, i = profile["name"], 2
        while profile["name"] in names:
            profile["name"] = f"{base} ({i})"
            i += 1
        profiles.append(profile)
        self.save(profiles)
        return profile
