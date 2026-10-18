import time
from threading import Lock

from scapy.all import Dot11, Dot11Deauth, Dot11Disas

from ..context import Module


class IDSModule(Module):
    name = "ids"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.pencere = 5.0
        self.esik = 20
        self.olaylar = []
        self.lock = Lock()
        self.son_alarm = 0.0

    def on(self, *a):
        if self.active:
            return
        self.ctx.sniffer.sub(self._handle)
        self.ctx.sniffer.start()
        self.active = True
        self.ctx.log(f"[ids] active (>{self.esik}/{self.pencere}s)", "ok")

    def _handle(self, p):
        if not p.haslayer(Dot11):
            return
        if not (p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas)):
            return
        d = p[Dot11]
        ap = d.addr3 or d.addr2 or "?"
        src = d.addr2 or "?"
        tip = "deauth" if p.haslayer(Dot11Deauth) else "disassoc"
        simdi = time.time()
        with self.lock:
            self.olaylar.append((simdi, ap, src, tip))
            self.olaylar = [e for e in self.olaylar if e[0] > simdi - self.pencere]
            son = [e for e in self.olaylar if e[1] == ap]
            if len(son) >= self.esik and simdi - self.son_alarm > self.pencere:
                self.son_alarm = simdi
                k = {}
                for _, _, s, _t in son:
                    k[s] = k.get(s, 0) + 1
                top = sorted(k.items(), key=lambda x: -x[1])[:3]
                self.ctx.log(f"[ALARM] {ap} {tip}! {len(son)}/{self.pencere}s "
                             f"src={top}", "err")

    def off(self):
        if not self.active:
            return
        self.ctx.sniffer.unsub(self._handle)
        self.active = False
        self.ctx.log(f"[ids] stopped ({len(self.olaylar)})", "ok")
