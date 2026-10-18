from dataclasses import dataclass, asdict, field
from threading import Event, Thread
from typing import Dict, Optional

from scapy.all import Dot11, Dot11Beacon

from ..context import Module
from ..dot11 import (kanal_bul, rssi_bul, pmf_durum, ssid_bul, rsn_analiz,
                     KANALLAR_24, KANALLAR_5, KANAL_FREKANS)
from ..iface import kanal_ayarla


@dataclass
class APBilgi:
    bssid: str
    ssid: str = "<gizli>"
    kanal: Optional[int] = None
    pmf_zorunlu: bool = False
    pmf_kabiliyetli: bool = False
    rssi: Optional[int] = None
    cipher: Optional[str] = None
    akm: Optional[str] = None
    wpa3: bool = False

    def to_dict(self):
        d = asdict(self)
        if self.kanal in KANAL_FREKANS:
            d["freq_mhz"] = KANAL_FREKANS[self.kanal]
            d["band"] = "5GHz" if self.kanal in KANALLAR_5 else "2.4GHz"
        return d


@dataclass
class IstemciBilgi:
    mac: str
    bssid: str
    son: float = field(default_factory=__import__("time").time)


class ScanModule(Module):
    name = "scan"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.apler: Dict[str, APBilgi] = {}
        self.istemciler: Dict[str, IstemciBilgi] = {}
        self.dur = Event()
        self.thread = None

    def on(self, *a):
        if self.active:
            return
        self.dur.clear()
        self.ctx.sniffer.sub(self._handle)
        self.ctx.sniffer.start()
        self.thread = Thread(target=self._hop, daemon=True)
        self.thread.start()
        self.active = True
        ch = "2.4+5 GHz" if self.ctx.all_channels else "2.4 GHz"
        self.ctx.log(f"[scan] started ({ch})", "ok")

    def _handle(self, p):
        if p.haslayer(Dot11Beacon):
            bssid = p[Dot11].addr2
            if bssid and bssid not in self.apler:
                mfpr, mfpc = pmf_durum(p)
                cipher, akm, wpa3 = rsn_analiz(p)
                ap = APBilgi(bssid=bssid, ssid=ssid_bul(p),
                             kanal=kanal_bul(p), pmf_zorunlu=mfpr,
                             pmf_kabiliyetli=mfpc, rssi=rssi_bul(p),
                             cipher=cipher, akm=akm, wpa3=wpa3)
                self.apler[bssid] = ap
                pmf = "PMF!" if mfpr else ("PMF" if mfpc else "-")
                band = "5G" if ap.kanal in KANALLAR_5 else "2.4"
                sec = "WPA3" if wpa3 else (ap.akm or "-")
                self.ctx.log(f"[scan] AP {bssid} ch={ap.kanal}({band}) "
                             f"{sec:8s} {pmf:4s} {ap.ssid}", "info")
        elif p.haslayer(Dot11) and p[Dot11].type == 2:
            d = p[Dot11]
            if d.FCfield & 0x1 and not (d.FCfield & 0x2):
                bssid, ist = d.addr1, d.addr2
            elif d.FCfield & 0x2 and not (d.FCfield & 0x1):
                ist, bssid = d.addr1, d.addr2
            else:
                return
            if ist and ist != "ff:ff:ff:ff:ff:ff" and ist not in self.istemciler:
                self.istemciler[ist] = IstemciBilgi(mac=ist, bssid=bssid)
                self.ctx.log(f"[scan] STA {ist} -> {bssid}", "dim")

    def _hop(self):
        import time
        kanallar = (KANALLAR_24 + KANALLAR_5
                    if self.ctx.all_channels else KANALLAR_24)
        while not self.dur.is_set():
            for k in kanallar:
                if self.dur.is_set():
                    return
                kanal_ayarla(self.ctx.iface, k)
                time.sleep(0.4)

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.thread:
            self.thread.join(timeout=2)
        self.ctx.sniffer.unsub(self._handle)
        self.active = False
        self.ctx.log(f"[scan] stopped ({len(self.apler)} APs)", "ok")

    def status(self):
        if self.active:
            return f"active ({len(self.apler)} APs, {len(self.istemciler)} STAs)"
        return "off"

    def json_dok(self):
        return {"apler": [a.to_dict() for a in self.apler.values()],
                "istemciler": [asdict(i) for i in self.istemciler.values()]}
