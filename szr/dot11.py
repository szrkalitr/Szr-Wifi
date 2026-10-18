import random
from typing import List, Optional, Tuple

from scapy.all import RadioTap, Dot11, Dot11Elt, EAPOL

RSN_ID = 48
DS_PARAM_ID = 3

KANALLAR_24 = list(range(1, 14))
KANALLAR_5 = [36, 40, 44, 48, 52, 56, 60, 64,
              100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
              149, 153, 157, 161, 165]
KANAL_FREKANS = {**{k: 2407 + k * 5 for k in KANALLAR_24},
                 **{k: 5000 + k * 5 for k in KANALLAR_5}}
REASON_KODLARI = [7, 3, 1, 2, 4, 15]

AKM_ISIM = {
    0x000FAC01: "802.1X", 0x000FAC02: "PSK", 0x000FAC03: "FT-802.1X",
    0x000FAC04: "FT-PSK", 0x000FAC05: "802.1X-SHA256",
    0x000FAC06: "PSK-SHA256", 0x000FAC08: "SAE", 0x000FAC09: "FT-SAE",
    0x000FAC12: "OWE",
}
CIPHER_ISIM = {
    0x000FAC00: "Use-Group", 0x000FAC01: "WEP40", 0x000FAC02: "TKIP",
    0x000FAC04: "CCMP", 0x000FAC05: "WEP104", 0x000FAC08: "GCMP",
    0x000FAC09: "GCMP-256",
}


def rastgele_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randrange(256) for _ in range(5))


def _elt_iter(p):
    elt = p.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        yield elt
        elt = elt.payload


def kanal_bul(p) -> Optional[int]:
    for elt in _elt_iter(p):
        if elt.ID == DS_PARAM_ID and elt.info:
            return int(elt.info[0])
            
    if p.haslayer(RadioTap) and p[RadioTap].Channel:
        freq = int(p[RadioTap].Channel)
        if freq == 2484:
            return 14
        elif 2412 <= freq <= 2472:
            return (freq - 2412) // 5 + 1
        elif 5000 <= freq <= 5895:
            return (freq - 5000) // 5
    return None


def rssi_bul(p) -> Optional[int]:
    try:
        return int(p[RadioTap].dBm_AntSignal)
    except Exception:
        return None


def pmf_durum(p) -> Tuple[bool, bool]:
    for elt in _elt_iter(p):
        if elt.ID == RSN_ID and elt.info and len(elt.info) >= 8:
            try:
                caps = (elt.info[-2] << 8) | elt.info[-1]
                return bool(caps & 0x0040), bool(caps & 0x0080)
            except Exception:
                pass
    return False, False


def ssid_bul(p) -> str:
    try:
        return p[Dot11Elt].info.decode(errors="ignore") or "<gizli>"
    except Exception:
        return "<gizli>"


def rsn_analiz(p) -> Tuple[Optional[str], Optional[str], bool]:
    for elt in _elt_iter(p):
        if elt.ID != RSN_ID or not elt.info or len(elt.info) < 12:
            continue
        info = elt.info
        try:
            i = 2
            i += 4
            pc = info[i] | (info[i + 1] << 8)
            i += 2
            cipher = None
            for _ in range(pc):
                suite = ((info[i] << 24) | (info[i + 1] << 16) |
                         (info[i + 2] << 8) | info[i + 3])
                if cipher is None and suite in CIPHER_ISIM:
                    cipher = CIPHER_ISIM[suite]
                i += 4
            ac = info[i] | (info[i + 1] << 8)
            i += 2
            akm = None
            wpa3 = False
            for _ in range(ac):
                suite = ((info[i] << 24) | (info[i + 1] << 16) |
                         (info[i + 2] << 8) | info[i + 3])
                name = AKM_ISIM.get(suite)
                if akm is None and name:
                    akm = name
                if name in ("SAE", "FT-SAE", "OWE"):
                    wpa3 = True
                i += 4
            return cipher, akm, wpa3
        except Exception:
            pass
    return None, None, False


def rsn_pmkid_listesi(rsn_info) -> List[bytes]:
    out = []
    try:
        i = 2
        i += 4
        pc = rsn_info[i] | (rsn_info[i + 1] << 8)
        i += 2
        i += 4 * pc
        ac = rsn_info[i] | (rsn_info[i + 1] << 8)
        i += 2
        i += 4 * ac
        i += 2
        if i + 2 > len(rsn_info):
            return out
        pmc = rsn_info[i] | (rsn_info[i + 1] << 8)
        i += 2
        for _ in range(pmc):
            if i + 16 > len(rsn_info):
                break
            out.append(bytes(rsn_info[i:i + 16]))
            i += 16
    except Exception:
        pass
    return out


def rsn_ie(p) -> Optional[bytes]:
    for elt in _elt_iter(p):
        if elt.ID == RSN_ID and elt.info:
            return bytes(elt.info)
    return None


def eapol_key_data(p) -> Optional[bytes]:
    if not p.haslayer(EAPOL):
        return None
    try:
        raw = bytes(p[EAPOL])
        if len(raw) < 4 or raw[1] != 3:
            return None
        off = 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16
        if off + 2 > len(raw):
            return None
        kdlen = raw[off] | (raw[off + 1] << 8)
        off += 2
        return bytes(raw[off:off + kdlen])
    except Exception:
        return None


def eapol_mesaj_tipi(p) -> Optional[str]:
    if not p.haslayer(EAPOL):
        return None
    try:
        raw = bytes(p[EAPOL])
        if len(raw) < 7 or raw[1] != 3:
            return None
        ki = (raw[5] << 8) | raw[6]
        ack = bool(ki & 0x80)
        mic = bool(ki & 0x100)
        sec = bool(ki & 0x200)
        if ack and not mic:
            return "M1"
        if not ack and mic and not sec:
            return "M2"
        if ack and mic:
            return "M3"
        if not ack and mic and sec:
            return "M4"
        return "EAPOL"
    except Exception:
        return None


def eapol_alanlar(p):
    if not p.haslayer(EAPOL):
        return None
    try:
        raw = bytes(p[EAPOL])
        if len(raw) < 99 or raw[1] != 3:
            return None
        keyver = raw[0]
        ki = (raw[5] << 8) | raw[6]
        mic = bytes(raw[81:81 + 16])
        nonce = bytes(raw[17:17 + 32])
        replay = bytes(raw[9:9 + 8])
        kdlen = raw[97] | (raw[98] << 8)
        eapol = bytearray(raw)
        eapol[81:81 + 16] = b"\x00" * 16
        return {"mic": mic, "nonce": nonce, "replay": replay,
                "eapol": bytes(eapol), "key_info": ki,
                "key_ack": bool(ki & 0x80), "key_mic": bool(ki & 0x100),
                "secure": bool(ki & 0x200), "keyver": keyver,
                "data_len": kdlen}
    except Exception:
        return None 
