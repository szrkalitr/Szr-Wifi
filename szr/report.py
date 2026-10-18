import time

from .dot11 import KANALLAR_5


def markdown(scan_mod, yol):
    apler = scan_mod.apler
    istemciler = scan_mod.istemciler
    lines = ["# szr-wifi Tarama Raporu", "",
             f"- Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"- AP sayısı: {len(apler)}",
             f"- İstemci sayısı: {len(istemciler)}", "",
             "## Erişim Noktaları", "",
             "| # | BSSID | SSID | Kanal | Band | RSSI | Cipher | AKM | PMF |",
             "|---|-------|------|-------|------|------|--------|-----|-----|"]
    for i, ap in enumerate(apler.values(), 1):
        pmf = "zorunlu" if ap.pmf_zorunlu else (
            "kabiliyetli" if ap.pmf_kabiliyetli else "-")
        band = "5G" if ap.kanal in KANALLAR_5 else "2.4"
        akm = "WPA3/SAE" if ap.wpa3 else (ap.akm or "-")
        lines.append(f"| {i} | `{ap.bssid}` | {ap.ssid} | {ap.kanal} | "
                     f"{band} | {ap.rssi} | {ap.cipher or '-'} | {akm} | {pmf} |")
    lines.append("")
    lines.append("## İstemciler")
    lines.append("")
    lines.append("| MAC | BSSID |")
    lines.append("|-----|-------|")
    for ist in istemciler.values():
        lines.append(f"| `{ist.mac}` | `{ist.bssid}` |")
    try:
        with open(yol, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return True
    except Exception:
        return False
