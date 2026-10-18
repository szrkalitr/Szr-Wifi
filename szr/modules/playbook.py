import os
import time
from threading import Event, Thread

from ..context import Module


class PlaybookModule(Module):
    name = "playbook"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.yol = None
        self.thread = None
        self.dur = Event()
        self.adimlar = []

    def on(self, yol=None, *a):
        if self.active:
            self.ctx.log("[playbook] already active", "warn")
            return
        if not yol:
            self.ctx.log("[playbook] usage: module playbook on <dosya.yaml>", "err")
            return
        if not os.path.isfile(yol):
            self.ctx.log(f"[playbook] dosya yok: {yol}", "err")
            return
        try:
            import yaml
        except ImportError:
            self.ctx.log("[playbook] PyYAML yok (pip install pyyaml)", "err")
            return
        try:
            with open(yol, "r", encoding="utf-8") as f:
                self.adimlar = yaml.safe_load(f).get("adimlar", [])
        except Exception as e:
            self.ctx.log(f"[playbook] yaml hatası: {e}", "err")
            return
        if not self.adimlar:
            self.ctx.log("[playbook] boş", "err")
            return
        self.yol = yol
        self.dur.clear()
        self.active = True
        self.thread = Thread(target=self._calistir, daemon=True)
        self.thread.start()
        self.ctx.log(f"[playbook] {len(self.adimlar)} adım başladı", "ok")

    def _calistir(self):
        for i, adim in enumerate(self.adimlar, 1):
            if self.dur.is_set():
                break
            tip = adim.get("tip")
            sure = float(adim.get("sure", 5))
            args = adim.get("args", {})
            self.ctx.log(f"[playbook] {i}/{len(self.adimlar)}: {tip} "
                         f"({sure}s)", "info")
            try:
                if tip == "scan":
                    s = self.ctx.modules["scan"]
                    s.on()
                    time.sleep(sure)
                    s.off()
                elif tip == "deauth":
                    b = args.get("bssid")
                    if not b:
                        continue
                    n = int(args.get("count", 100))
                    self.ctx.modules["deauth"].once(
                        b, args.get("client"), n, float(args.get("jitter", 0)))
                    time.sleep(sure)
                elif tip == "eapol":
                    e = self.ctx.modules["eapol"]
                    e.on()
                    time.sleep(sure)
                    e.off()
                elif tip == "pmkid":
                    b = args.get("bssid")
                    if not b:
                        continue
                    self.ctx.modules["pmkid"].once(
                        b, args.get("ssid", ""), int(sure))
                elif tip == "wps":
                    b = args.get("bssid")
                    if not b:
                        continue
                    self.ctx.modules["wps"].once(
                        b, args.get("channel"), int(sure))
                elif tip == "portal":
                    self.ctx.modules["portal"].on(
                        args.get("ssid"), args.get("template"),
                        args.get("channel"))
                    time.sleep(sure)
                elif tip in ("bekle", "sleep"):
                    time.sleep(sure)
            except Exception as e:
                self.ctx.log(f"[playbook] adım hatası: {e}", "err")
        self.active = False
        self.ctx.log("[playbook] bitti", "ok")

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.thread:
            self.thread.join(timeout=3)
        self.active = False
        self.ctx.log("[playbook] durduruldu", "ok")

    def status(self):
        return (f"active ({os.path.basename(self.yol or '')})"
                if self.active else "off")
