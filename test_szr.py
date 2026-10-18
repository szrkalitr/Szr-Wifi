from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt

from szr.dot11 import kanal_bul, rsn_pmkid_listesi, pmf_durum, rsn_analiz
from szr.hashcat import hashcat_01


def test_kanal_bul_radiotap():
    p = (RadioTap(Channel=6) /
         Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
               addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") /
         Dot11Beacon())
    assert kanal_bul(p) == 6


def test_kanal_bul_ds_param():
    p = (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
               addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") /
         Dot11Beacon() /
         Dot11Elt(ID=0, info=b"Test") /
         Dot11Elt(ID=3, info=bytes([11])))
    assert kanal_bul(p) == 11


def test_rsn_pmkid_gecersiz():
    assert rsn_pmkid_listesi(b"\x01\x00") == []


def test_rsn_analiz_bos():
    p = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
              addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon()
    c, a, w = rsn_analiz(p)
    assert c is None and a is None and not w


def test_hashcat_01():
    pm = b"\x00" * 16
    s = hashcat_01(pm, "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "Test")
    assert s.startswith("WPA*01*")
    assert "aabbccddeeff" in s
    assert "112233445566" in s
    assert "54657374" in s


def test_pmf_bos():
    p = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
              addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon()
    mfpr, mfpc = pmf_durum(p)
    assert not mfpr and not mfpc
