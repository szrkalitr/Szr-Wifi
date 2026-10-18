import subprocess


def monitor_mu(arayuz):
    try:
        out = subprocess.check_output(["iw", "dev", arayuz, "info"],
                                      text=True, stderr=subprocess.DEVNULL)
        return "type monitor" in out
    except Exception:
        return False


def kanal_ayarla(arayuz, kanal):
    res = subprocess.run(["iw","dev",arayuz,"set","channel",str(kanal)], capture_output=True,text=True)
    if res.returncode != 0:
      print("kanaldeğişmedi")

def arac_var(mi):
    import shutil
    return shutil.which(mi) is not None
