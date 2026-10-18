from scapy.all import Dot11, Dot11ProbeReq

from ..context import Module


class ProbeModule(Module):
    name = "probe"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.kayitlar = {}

    def on(self, *a):
        if self.active:
            return
        self.ctx.sniffer.sub(self._handle)
        self.ctx.sniffer.start()
        self.active = True
        self.ctx.log("[probe] started", "ok")

    def _handle(self, p):
        if not p.haslayer(Dot11ProbeReq):
            return
        mac = p[Dot11].addr2
        if not mac:
            return
        try:
            ssid = p[Dot11Elt].info.decode(errors="ignore")
        except Exception:
            ssid = ""
        if not ssid:
            return
        s = self.kayitlar.setdefault(mac, set())
        if ssid not in s:
            s.add(ssid)
            self.ctx.log(f"[probe] {mac} -> {ssid}", "info")

    def off(self):
        if not self.active:
            return
        self.ctx.sniffer.unsub(self._handle)
        self.active = False
        self.ctx.log(f"[probe] stopped ({len(self.kayitlar)} devices)", "ok")

    def status(self):
        return f"active ({len(self.kayitlar)} devices)" if self.active else "off"
