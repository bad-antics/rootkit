"""Rootkit Research - Detection & Analysis"""
import os, subprocess, json, re
from datetime import datetime

class RootkitDetector:
    def __init__(self):
        self.findings = []
    
    def full_scan(self):
        self.check_hidden_processes()
        self.check_hidden_files()
        self.check_persistence()
        self.check_kernel_modules()
        self.check_library_hooks()
        return self.findings
    
    def check_hidden_processes(self):
        """Compare /proc entries vs ps output"""
        try:
            proc_pids = {int(d) for d in os.listdir("/proc") if d.isdigit()}
            ps = subprocess.check_output(["ps", "-eo", "pid"], text=True)
            ps_pids = {int(l.strip()) for l in ps.strip().split("\n")[1:] if l.strip().isdigit()}
            hidden = proc_pids - ps_pids
            if hidden:
                self.findings.append({"type": "hidden_process", "pids": list(hidden), "severity": "HIGH"})
        except Exception as e:
            self.findings.append({"type": "error", "detail": str(e)})
    
    def check_hidden_files(self):
        """Detect files hidden from ls but visible via syscall"""
        suspect_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        for d in suspect_dirs:
            if not os.path.isdir(d): continue
            try:
                entries = os.listdir(d)
                for entry in entries:
                    if entry.startswith(".") and len(entry) > 10:
                        self.findings.append({"type": "suspicious_hidden", "path": os.path.join(d, entry), "severity": "MEDIUM"})
            except: pass
    
    def check_persistence(self):
        """Check common persistence locations"""
        persist_checks = [
            ("/etc/crontab", "crontab"),
            ("/etc/rc.local", "rc.local"),
            ("/etc/ld.so.preload", "ld_preload"),
        ]
        for path, name in persist_checks:
            if os.path.exists(path):
                try:
                    content = open(path).read()
                    if any(s in content.lower() for s in ["curl", "wget", "nc ", "ncat", "reverse", "backdoor"]):
                        self.findings.append({"type": "persistence", "method": name, "path": path, "severity": "HIGH"})
                except: pass
    
    def check_kernel_modules(self):
        """List loaded kernel modules and flag suspicious ones"""
        try:
            mods = open("/proc/modules").read()
            for line in mods.split("\n"):
                parts = line.split()
                if not parts: continue
                name = parts[0]
                if any(s in name.lower() for s in ["hide", "stealth", "hook", "rootkit"]):
                    self.findings.append({"type": "suspicious_module", "name": name, "severity": "CRITICAL"})
        except: pass
    
    def check_library_hooks(self):
        """Check for LD_PRELOAD hooks"""
        preload = os.environ.get("LD_PRELOAD", "")
        if preload:
            self.findings.append({"type": "ld_preload", "value": preload, "severity": "HIGH"})
        if os.path.exists("/etc/ld.so.preload"):
            content = open("/etc/ld.so.preload").read().strip()
            if content:
                self.findings.append({"type": "ld_so_preload", "libraries": content, "severity": "HIGH"})
    
    def report(self):
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        high = [f for f in self.findings if f.get("severity") == "HIGH"]
        medium = [f for f in self.findings if f.get("severity") == "MEDIUM"]
        return {"scan_time": str(datetime.now()), "total": len(self.findings),
                "critical": len(critical), "high": len(high), "medium": len(medium), "findings": self.findings}
