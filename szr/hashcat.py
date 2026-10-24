def hashcat_01(pmkid, ap, sta, essid):
    return "WPA*01*%s*%s*%s*%s***" % (
        pmkid.hex(), ap.replace(":", "").lower(), sta.replace(":", "").lower(), essid.encode().hex())

def hashcat_02(mic, ap, sta, essid, anonce, snonce, eapol, keyver=2):
    return "WPA*02*%s*%s*%s*%s*%s*%s*%s*%02x*00*%d" % (
        mic.hex(), ap.replace(":", "").lower(), sta.replace(":", "").lower(),
        essid.encode().hex(), anonce.hex(), snonce.hex(), eapol.hex(), keyver, len(eapol))
