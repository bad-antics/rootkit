"""Stealth technique analysis"""
import os, stat

class StealthAnalyzer:
    @staticmethod
    def find_suid_binaries(directory="/usr/bin"):
        """Find SUID binaries that could be exploited"""
        suid = []
        for root, dirs, files in os.walk(directory):
            for f in files:
                path = os.path.join(root, f)
                try:
                    st = os.stat(path)
                    if st.st_mode & stat.S_ISUID:
                        suid.append({"path": path, "owner": st.st_uid, "size": st.st_size})
                except: pass
        return suid
    
    @staticmethod
    def check_proc_hiding():
        """Check if /proc shows all processes"""
        try:
            proc_count = len([d for d in os.listdir("/proc") if d.isdigit()])
            return {"proc_entries": proc_count, "suspicious": proc_count < 10}
        except:
            return {"error": "cannot read /proc"}
    
    @staticmethod
    def detect_timestomping(filepath):
        """Check for timestamp manipulation"""
        try:
            st = os.stat(filepath)
            atime = st.st_atime
            mtime = st.st_mtime
            ctime = st.st_ctime
            if mtime < ctime:
                return {"suspicious": True, "reason": "mtime before ctime"}
            return {"suspicious": False}
        except:
            return {"error": "cannot stat file"}
