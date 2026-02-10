"""Rootkit Research Config"""
class RootkitConfig:
    HIDE_PROCESSES = True
    HIDE_FILES = True
    HIDE_NETWORK = True
    PERSISTENCE_METHODS = ["cron", "systemd", "rc.local", "bashrc", "ld_preload"]
    LOG_FILE = "rootkit_research.log"
    SAFE_MODE = True
