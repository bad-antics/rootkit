"""Persistence mechanism analysis"""
import os, json

class PersistenceAnalyzer:
    LOCATIONS = {
        "cron_user": "~/.crontab",
        "cron_system": "/etc/crontab",
        "cron_d": "/etc/cron.d/",
        "systemd_user": "~/.config/systemd/user/",
        "systemd_system": "/etc/systemd/system/",
        "rc_local": "/etc/rc.local",
        "bashrc": "~/.bashrc",
        "profile": "~/.profile",
        "init_d": "/etc/init.d/",
        "ld_preload": "/etc/ld.so.preload",
        "ssh_rc": "~/.ssh/rc",
        "authorized_keys": "~/.ssh/authorized_keys",
    }
    
    def analyze_all(self):
        results = {}
        for name, path in self.LOCATIONS.items():
            path = os.path.expanduser(path)
            results[name] = self._check_location(path)
        return results
    
    def _check_location(self, path):
        if not os.path.exists(path):
            return {"exists": False}
        info = {"exists": True, "writable": os.access(path, os.W_OK)}
        if os.path.isfile(path):
            try:
                stat = os.stat(path)
                info["size"] = stat.st_size
                info["modified"] = stat.st_mtime
            except: pass
        return info
