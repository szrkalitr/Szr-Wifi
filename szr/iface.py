import subprocess
import shutil

def monitor_mu(arayuz):
    try:
        out = subprocess.check_output(["iw", "dev", arayuz, "info"], text=True, stderr=subprocess.DEVNULL)
        return "type monitor" in out
    except Exception:
        return False

def kanal_ayarla(arayuz, kanal):
    res = subprocess.run(["iw", "dev", arayuz, "set", "channel", str(kanal)], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"\033[31m[!] Kanal {kanal} değiştirilemedi: {res.stderr.strip()}\033[0m")

def arac_var(mi):
    return shutil.which(mi) is not None

def txpower_ayarla(arayuz, dbm=30):
    subprocess.run(["iw", "dev", arayuz, "set", "txpower", "fixed", str(dbm * 100)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
