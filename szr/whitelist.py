import os

BEYAZ_LISTE_DOSYA = "whitelist.txt"


def oku():
    if not os.path.isfile(BEYAZ_LISTE_DOSYA):
        return set()
    out = set()
    try:
        with open(BEYAZ_LISTE_DOSYA, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    out.add(line)
    except Exception:
        pass
    return out
