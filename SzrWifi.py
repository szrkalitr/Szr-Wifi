import argparse
import json
import logging
import os
import signal
import sys
import time
from threading import Thread

from scapy.all import conf

from szr.context import Context, set_quiet
from szr.iface import monitor_mu, kanal_ayarla
from szr.dot11 import KANALLAR_5
from szr.modules import yukle
from szr.report import markdown as rapor_markdown
from szr.whitelist import oku as wl_oku, BEYAZ_LISTE_DOSYA

TOOL_NAME = "szr-wifi"
TOOL_VERSION = "3.0"
TOOL_PROMPT = f"{TOOL_NAME} > "
BANNER_DOSYA = "banner.txt"
TEMPLATES_DIR = "templates"

log = logging.getLogger(TOOL_NAME)
_aktif_ctx = None

def banner_yaz():
    if os.path.isfile(BANNER_DOSYA):
        try:
            with open(BANNER_DOSYA, "r", encoding="utf-8") as f:
                sys.stdout.write(f.read())
                sys.stdout.write("\n")
                sys.stdout.flush()
        except Exception:
            pass

def _json_oku(y):
    with open(y, "r", encoding="utf-8") as f:
        return json.load(f)

def _json_hedef_coz(a, bssid, kanal=None, ssid=None):
    if not getattr(a, "from_json", None):
        return bssid, kanal, ssid
    try:
        sec = _json_oku(a.from_json)["apler"][int(bssid) - 1]
        return sec["bssid"], kanal or sec.get("kanal"), ssid or sec.get("ssid", "")
    except Exception as e:
        log.error("[!] JSON: %s", e)
        sys.exit(1)

def cli_scan(a):
    ctx = _ctx(a)
    s = ctx.modules["scan"]
    s.on()
    try:
        time.sleep(a.time)
    finally:
        s.off()
    if s.apler:
        print("\n%-3s %-17s %-4s %-24s %-6s %-4s %-6s %-8s %s" %
              ("#", "BSSID", "CH", "SSID", "RSSI", "BAND", "CIPHER", "AKM", "PMF"))
        print("-" * 100)
        for i, ap in enumerate(s.apler.values(), 1):
            pmf = "zorunlu" if ap.pmf_zorunlu else ("kab." if ap.pmf_kabiliyetli else "-")
            band = "5G" if ap.kanal in KANALLAR_5 else "2.4"
            akm = "WPA3/SAE" if ap.wpa3 else (ap.akm or "-")
            print("%-3d %-17s %-4s %-24s %-6s %-4s %-6s %-8s %s" %
                  (i, ap.bssid, str(ap.kanal), ap.ssid[:24], str(ap.rssi), band, ap.cipher or "-", akm, pmf))
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump(s.json_dok(), f, ensure_ascii=False, indent=2)
        log.info("[+] %s", a.output)

def cli_deauth(a):
    b, k, _ = _json_hedef_coz(a, a.bssid, a.channel)
    ctx = _ctx(a)
    m = ctx.modules["deauth"]
    if k:
        kanal_ayarla(ctx.iface, int(k))
    m.once(b, a.client, a.count, a.jitter)
    try:
        time.sleep(a.count * 0.05 + 0.5)
    except KeyboardInterrupt:
        pass

def cli_eapol(a):
    ctx = _ctx(a)
    if a.channel:
        kanal_ayarla(ctx.iface, a.channel)
    m = ctx.modules["eapol"]
    if a.from_json and a.bssid:
        _, k, _ = _json_hedef_coz(a, a.bssid, a.channel)
        if k:
            kanal_ayarla(ctx.iface, int(k))
    m.on()
    try:
        time.sleep(a.time)
    except KeyboardInterrupt:
        pass
    finally:
        m.off()
    if a.pcap:
        m.save_pcap(a.pcap)
    if a.output and a.output.endswith(".22000"):
        m.save_22000(a.output)

def cli_pmkid(a):
    b, k, ss = _json_hedef_coz(a, a.bssid, a.channel, a.ssid)
    ctx = _ctx(a)
    if k:
        kanal_ayarla(ctx.iface, int(k))
    m = ctx.modules["pmkid"]
    m.once(b, ss or "", a.time)
    try:
        time.sleep(a.time + 0.5)
    except KeyboardInterrupt:
        pass
    if a.output:
        m.save_22000(a.output)

def cli_probe(a):
    ctx = _ctx(a)
    if a.channel:
        kanal_ayarla(ctx.iface, a.channel)
    m = ctx.modules["probe"]
    m.on()
    try:
        time.sleep(a.time)
    except KeyboardInterrupt:
        pass
    finally:
        m.off()
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump({mac: sorted(s) for mac, s in m.kayitlar.items()}, f, ensure_ascii=False, indent=2)
        log.info("[+] %d MAC -> %s", len(m.kayitlar), a.output)

def cli_ids(a):
    ctx = _ctx(a)
    if a.channel:
        kanal_ayarla(ctx.iface, a.channel)
    m = ctx.modules["ids"]
    m.esik = a.threshold
    m.pencere = a.window
    m.on()
    try:
        time.sleep(a.time)
    except KeyboardInterrupt:
        pass
    finally:
        m.off()

def cli_flood(a):
    ctx = _ctx(a)
    ctx.modules["flood"].once(a.count, a.time, a.all_channels)

def cli_wps(a):
    ctx = _ctx(a)
    m = ctx.modules["wps"]
    m.once(a.bssid, a.channel, a.time)
    try:
        time.sleep(a.time + 1)
    except KeyboardInterrupt:
        pass

def cli_portal(a):
    ctx = _ctx(a)
    m = ctx.modules["portal"]
    m.on(a.ssid, a.template, a.channel)
    if not m.active:
        sys.exit(1)
    try:
        while m.active:
            time.sleep(1)
    except KeyboardInterrupt:
        m.off()
        if a.creds:
            m.save_creds(a.creds)

def _ctx(a, mitm=False):
    ctx = Context(a.iface, mitm_enabled=mitm, all_channels=getattr(a, "all_channels", False))
    ctx.modules = yukle(ctx)
    return ctx

HELP = f"""
Commands:
  modules                          modül + durum
  module <name> on [args]         modül aç
  module <name> off               modül kapat
  aps                             AP listesi
  templates                       captive portal şablonları
  set channel <N>                 kanal sabitle
  save <path>                     .pcap / .22000 / .creds
  report <dosya.md>               tarama raporu
  whitelist                       beyaz liste
  playbook <dosya.yaml>           playbook çalıştır

Shortcuts:
  scan [sec]
  deauth <bssid> [client] [n]
  pmkid <bssid> [ssid] [sec]
  flood <n> [sec]
  wps <bssid> [ch] [sec]
  portal <ssid> <template> [ch]

Modules: scan, probe, eapol, deauth, pmkid, ids, flood, wps, portal, sticky, playbook (+ mitm)
"""

def handle(line, ctx):
    parts = line.split()
    if not parts:
        return
    cmd, args = parts[0].lower(), parts[1:]

    if cmd in ("exit", "quit", "q"):
        ctx.should_exit = True
        return
    if cmd in ("help", "?"):
        ctx.tui.raw(HELP)
        return
    if cmd == "clear":
        os.system("clear")
        return

    if cmd == "modules":
        for name, m in ctx.modules.items():
            ctx.tui.write(f"  {name:10s} {m.status()}", "info")
        return

    if cmd == "templates":
        d = os.path.join(os.getcwd(), TEMPLATES_DIR)
        if not os.path.isdir(d):
            ctx.tui.write(f"[templates] {d} yok", "warn")
            return
        for t in sorted(os.listdir(d)):
            full = os.path.join(d, t)
            if os.path.isdir(full):
                has = os.path.isfile(os.path.join(full, "index.html"))
                mark = "OK" if has else "eksik index.html"
                ctx.tui.write(f"  {t:20s} {mark}", "info" if has else "warn")
        return

    if cmd == "module":
        if len(args) < 2:
            ctx.tui.write("usage: module <name> <on|off|status> [args]", "warn")
            return
        name, action, rest = args[0], args[1].lower(), args[2:]
        m = ctx.modules.get(name)
        if not m:
            ctx.tui.write(f"unknown module: {name}", "err")
            return
        if action == "on":
            m.on(*rest)
        elif action == "off":
            m.off()
        elif action == "status":
            ctx.tui.write(f"{name}: {m.status()}", "info")
        return

    if cmd == "aps":
        s = ctx.modules.get("scan")
        if not s or not s.apler:
            ctx.tui.write("no APs", "warn")
            return
        for i, ap in enumerate(s.apler.values(), 1):
            pmf = "PMF!" if ap.pmf_zorunlu else ("PMF" if ap.pmf_kabiliyetli else "-")
            band = "5G" if ap.kanal in KANALLAR_5 else "2.4"
            sec = "WPA3" if ap.wpa3 else (ap.akm or "-")
            ctx.tui.write(f"  {i:3d}) {ap.bssid} ch={ap.kanal}({band}) {sec:8s} {pmf:4s} {ap.ssid}", "info")
        return

    if cmd == "set":
        if len(args) < 2:
            ctx.tui.write("usage: set channel <N>", "warn")
            return
        if args[0] == "channel":
            try:
                kanal_ayarla(ctx.iface, int(args[1]))
                ctx.tui.write(f"channel -> {args[1]}", "ok")
            except Exception as e:
                ctx.tui.write(f"error: {e}", "err")
        return

    if cmd == "save":
        if not args:
            ctx.tui.write("usage: save <path>", "warn")
            return
        p = args[0]
        if p.endswith(".creds"):
            ctx.modules["portal"].save_creds(p)
        elif p.endswith(".22000"):
            em = ctx.modules["eapol"]
            if em.hashcat_lines:
                em.save_22000(p)
            else:
                ctx.modules["pmkid"].save_22000(p)
        else:
            ctx.modules["eapol"].save_pcap(p)
        return

    if cmd == "report":
        if not args:
            ctx.tui.write("usage: report <dosya.md>", "warn")
            return
        if rapor_markdown(ctx.modules["scan"], args[0]):
            ctx.tui.write(f"[report] {args[0]}", "ok")
        else:
            ctx.tui.write("[report] yazma hatası", "err")
        return

    if cmd == "whitelist":
        wl = wl_oku()
        if not wl:
            ctx.tui.write(f"[whitelist] {BEYAZ_LISTE_DOSYA} boş/yok", "warn")
            return
        for m in sorted(wl):
            ctx.tui.write(f"  {m}", "info")
        return

    if cmd == "playbook":
        if not args:
            ctx.tui.write("usage: playbook <dosya.yaml>", "warn")
            return
        ctx.modules["playbook"].on(args[0])
        return

    if cmd == "scan":
        sec = int(args[0]) if args else 15
        s = ctx.modules["scan"]
        if s.active:
            ctx.tui.write("scan active", "warn")
            return
        s.on()
        def _stop():
            time.sleep(sec)
            s.off()
        Thread(target=_stop, daemon=True).start()
        return

    if cmd == "deauth":
        if not args:
            ctx.tui.write("usage: deauth <bssid> [client] [n]", "warn")
            return
        b = args[0]
        c = args[1] if len(args) > 1 else None
        try:
            n = int(args[2]) if len(args) > 2 else 100
        except ValueError:
            ctx.tui.write("Hata: Sayı bekleniyordu.", "err")
            return
        ctx.modules["deauth"].once(b, c, n)
        return

    if cmd == "pmkid":
        if not args:
            ctx.tui.write("usage: pmkid <bssid> [ssid] [sec]", "warn")
            return
        b = args[0]
        ss = args[1] if len(args) > 1 else ""
        try:
            n = int(args[2]) if len(args) > 2 else 20
        except ValueError:
            ctx.tui.write("Hata: Sayı bekleniyordu.", "err")
            return
        ctx.modules["pmkid"].once(b, ss, n)
        return

    if cmd == "flood":
        try:
            n = int(args[0]) if args else 50
            d = int(args[1]) if len(args) > 1 else 10
        except ValueError:
            ctx.tui.write("Hata: Sayı bekleniyordu.", "err")
            return
        ctx.modules["flood"].once(n, d, ctx.all_channels)
        return

    if cmd == "wps":
        if not args:
            ctx.tui.write("usage: wps <bssid> [ch] [sec]", "warn")
            return
        b = args[0]
        c = args[1] if len(args) > 1 else None
        try:
            d = int(args[2]) if len(args) > 2 else 60
        except ValueError:
            ctx.tui.write("Hata: Sayı bekleniyordu.", "err")
            return
        ctx.modules["wps"].once(b, c, d)
        return

    if cmd == "portal":
        if len(args) < 2:
            ctx.tui.write("usage: portal <ssid> <template> [ch]", "warn")
            return
        ctx.modules["portal"].on(args[0], args[1], args[2] if len(args) > 2 else None)
        return

    ctx.tui.write(f"unknown: {cmd} (help)", "err")

def repl(ctx):
    while not ctx.should_exit:
        try:
            line = input(TOOL_PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        try:
            handle(line, ctx)
        except Exception as e:
            ctx.tui.write(f"error: {e}", "err")

def _sigint(sig, frame):
    global _aktif_ctx
    log.warning("[!] Ctrl+C")
    if _aktif_ctx:
        _aktif_ctx.shutdown()
    sys.exit(130)

def _argparse():
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="802.11 pentest aracı")
    p.add_argument("-i", "--iface", default="wlan0mon")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--mitm", action="store_true")

    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan")
    s.add_argument("-t", "--time", type=int, default=15)
    s.add_argument("-o", "--output")
    s.add_argument("--all-channels", action="store_true")
    s.set_defaults(func=cli_scan)

    d = sub.add_parser("deauth")
    d.add_argument("-b", "--bssid", required=True)
    d.add_argument("-c", "--client")
    d.add_argument("-C", "--channel", type=int)
    d.add_argument("-n", "--count", type=int, default=100)
    d.add_argument("--jitter", type=float, default=0.0)
    d.add_argument("--from-json")
    d.set_defaults(func=cli_deauth)

    e = sub.add_parser("eapol")
    e.add_argument("-b", "--bssid")
    e.add_argument("-C", "--channel", type=int)
    e.add_argument("-t", "--time", type=int, default=60)
    e.add_argument("-p", "--pcap")
    e.add_argument("-o", "--output")
    e.add_argument("--from-json")
    e.set_defaults(func=cli_eapol)

    pk = sub.add_parser("pmkid")
    pk.add_argument("-b", "--bssid", required=True)
    pk.add_argument("--ssid")
    pk.add_argument("-C", "--channel", type=int)
    pk.add_argument("-t", "--time", type=int, default=20)
    pk.add_argument("-o", "--output")
    pk.add_argument("--from-json")
    pk.set_defaults(func=cli_pmkid)

    pr = sub.add_parser("probe")
    pr.add_argument("-C", "--channel", type=int)
    pr.add_argument("-t", "--time", type=int, default=60)
    pr.add_argument("-o", "--output")
    pr.set_defaults(func=cli_probe)

    ids = sub.add_parser("ids")
    ids.add_argument("-C", "--channel", type=int)
    ids.add_argument("-t", "--time", type=int, default=60)
    ids.add_argument("--window", type=float, default=5.0)
    ids.add_argument("--threshold", type=int, default=20)
    ids.set_defaults(func=cli_ids)

    fl = sub.add_parser("flood")
    fl.add_argument("-n", "--count", type=int, default=50)
    fl.add_argument("-t", "--time", type=int, default=15)
    fl.add_argument("--all-channels", action="store_true")
    fl.set_defaults(func=cli_flood)

    w = sub.add_parser("wps")
    w.add_argument("-b", "--bssid", required=True)
    w.add_argument("-C", "--channel", type=int)
    w.add_argument("-t", "--time", type=int, default=60)
    w.set_defaults(func=cli_wps)

    po = sub.add_parser("portal")
    po.add_argument("--ssid", required=True)
    po.add_argument("--template", required=True)
    po.add_argument("-C", "--channel", type=int)
    po.add_argument("--creds")
    po.set_defaults(func=cli_portal)

    return p

def main():
    global _aktif_ctx
    p = _argparse()
    a = p.parse_args()

    if a.mitm and a.cmd:
        p.error("--mitm TUI modu içindir; subcommand ile kullanılamaz")

    set_quiet(a.quiet)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(message)s")
    conf.verb = 0
    signal.signal(signal.SIGINT, _sigint)
    banner_yaz()

    if not monitor_mu(a.iface):
        log.warning("[!] %s monitor modda değil", a.iface)

    if a.mitm:
        ctx = Context(a.iface, mitm_enabled=True, all_channels=getattr(a, "all_channels", False))
        ctx.modules = yukle(ctx)
        _aktif_ctx = ctx
        try:
            repl(ctx)
        finally:
            ctx.shutdown()
        return

    if not a.cmd:
        p.print_help()
        sys.exit(1)

    ctx = _ctx(a)
    _aktif_ctx = ctx
    try:
        a.func(a)
    finally:
        ctx.shutdown()

if __name__ == "__main__":
    main()
