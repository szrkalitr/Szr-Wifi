from scapy.all import Dot11, wrpcap

from ..context import Module
from ..dot11 import eapol_mesaj_tipi, eapol_alanlar
from ..hashcat import hashcat_02


class EapolModule(Module):
    name = "eapol"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.mesajlar = {}
        self.paketler = []
        self.handshakes = []
        self.hashcat_lines = []
        self._pending = {}
        self.ssid_cache = {}

    def on(self, *a):
        if self.active:
            return
        self.ctx.sniffer.sub(self._handle)
        self.ctx.sniffer.start()
        self.active = True
        self.ctx.log("[eapol] watching (M1+M2 → WPA*02*)", "ok")

    def _handle(self, p):
        tip = eapol_mesaj_tipi(p)
        if not tip or not p.haslayer(Dot11):
            return
        d = p[Dot11]
        alanlar = eapol_alanlar(p)
        if not alanlar:
            return
        pair = tuple(sorted([d.addr1 or "", d.addr2 or ""]))
        self.mesajlar.setdefault(pair, set()).add(tip)
        self.paketler.append(p)
        self.ctx.log(f"[eapol] {tip} {pair[0]} <-> {pair[1]}", "dim")
        slot = self._pending.setdefault(pair, {})
        if tip == "M1":
            slot["M1"] = alanlar
        elif tip == "M2":
            slot["M2"] = alanlar
        if "M1" in slot and "M2" in slot and pair not in self.handshakes:
            m1, m2 = slot["M1"], slot["M2"]
            ap = d.addr1 if d.FCfield & 0x1 else d.addr2
            sta = d.addr2 if d.FCfield & 0x1 else d.addr1
            if m2["mic"] == b"\x00" * 16:
                return
            essid = self.ssid_cache.get(ap, "")
            line = hashcat_02(m2["mic"], ap, sta, essid,
                              m1["nonce"], m2["nonce"], m2["eapol"])
            if line not in self.hashcat_lines:
                self.hashcat_lines.append(line)
                self.handshakes.append(pair)
                self.ctx.log(f"[eapol] *** HANDSHAKE {sta} <-> {ap} "
                             f"→ WPA*02* ***", "ok")

    def off(self):
        if not self.active:
            return
        self.ctx.sniffer.unsub(self._handle)
        self.active = False
        self.ctx.log(f"[eapol] stopped ({len(self.handshakes)} hs, "
                     f"{len(self.hashcat_lines)} WPA*02*)", "ok")

    def save_pcap(self, path):
        if not self.paketler:
            self.ctx.log("[eapol] no packets", "warn")
            return
        try:
            wrpcap(path, self.paketler)
            self.ctx.log(f"[eapol] {len(self.paketler)} pkts → {path}", "ok")
        except Exception as e:
            self.ctx.log(f"[eapol] pcap err: {e}", "err")

    def save_22000(self, path):
        if not self.hashcat_lines:
            self.ctx.log("[eapol] no WPA*02*", "warn")
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.hashcat_lines) + "\n")
            self.ctx.log(f"[eapol] {len(self.hashcat_lines)} → {path}", "ok")
        except Exception as e:
            self.ctx.log(f"[eapol] save err: {e}", "err")

    def status(self):
        if self.active:
            return (f"active ({len(self.handshakes)} hs, "
                    f"{len(self.hashcat_lines)} WPA*02*)")
        return "off"
