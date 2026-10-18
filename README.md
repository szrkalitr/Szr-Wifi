Szr-Wifi

Szr-Wifi, Kali Linux ve benzeri pentest dağıtımları için geliştirilmiş, modüler yapıya sahip, gelişmiş bir 802.11 (Wi-Fi) denetim ve sızma testi aracıdır.

Sadece 2.4 GHz değil, 5 GHz (DFS kanalları dahil) üzerinde de tam destek sunar. Kendi geliştirdiği monitor.sh betiği ile airmon-ng'ye alternatif, daha temiz ve kontrollü bir monitor mod yönetimi sağlar.

    ⚠️ YASAL UYARI: Bu araç sadece kendi laboratuvarınızda, eğitim (CTF) amaçlı veya yazılı izin (pentest sözleşmesi) aldığınız sistemlerde kullanılmak üzere tasarlanmıştır. İzinsiz sistemlere yapılan saldırılar Türkiye'de ve dünyada yasal suç teşkil eder (TCK 243/244). Geliştiriciler hiçbir kötüye kullanımdan sorumlu tutulamaz.

🚀 Öne Çıkan Özellikler

    Çift Arayüz (CLI & TUI): Standart komut satırı argümanlarıyla hızlı işlemler yapabilir veya --mitm parametresiyle szr-wifi > interaktif kabuğuna (REPL) geçip modülleri canlı yönetebilirsiniz.

    Tam Kanal Desteği: Frekans (MHz) ve Kanal (CH) karmaşasını çözer; 2.4 GHz ve 5 GHz ağlarını doğru bant genişliğinde listeler.

    Gelişmiş Monitor Yönetimi: airmon-ng bağımlılığı olmadan, iw ve nmcli ile kendi monitor.sh betiği üzerinden arayüzü monitor veya managed moda geçirebilir.

    Modüler Saldırı Araçları: Deauth, PMKID (Clientless), EAPOL Handshake (WPA*02*), Evil Twin ve Captive Portal.

    Akıllı Deauth: Deauth ve Disassoc paketlerini harmanlayarak gönderir, Reason Code döngüsü ve Jitter (rastgele gecikme) desteği sunar.

    IDS / Savunma Modu: Bulunduğunuz ortamda bir deauth saldırısı olup olmadığını tespit eder.

    Playbook Desteği: YAML dosyaları ile "Tara -> Deauth At -> Handshake Yakala" gibi saldırı zincirlerini otomatikleştirir.

🛠️ Kurulum
1. Sistem Gereksinimleri

Aşağıdaki paketlerin sisteminizde kurulu olduğundan emin olun (Debian/Kali için):
sudo apt update
sudo apt install aircrack-ng hostapd dnsmasq reaver iw
2. Python Bağımlılıkları

pip install scapy flask dnslib pyyaml
3. Projeyi Hazırlayın

git clone <proje_repo_url>
cd Szr-Wifi
chmod +x monitor.sh
💻 Kullanım
Monitor Moda Geçiş (monitor.sh)

Aracı kullanmadan önce Wi-Fi kartınızı monitor moda almanız gerekir. Kendi yazdığımız betik, airmon-ng'nin aksine arka plan servislerini tamamen öldürmeden, sadece ilgili arayüzü serbest bırakarak işlem yapar.

İnteraktif Menü:
sudo ./monitor.sh

CLI ile (Hızlı):
Mevcut wlan0'ı monitor yap (wlan0mon oluşturmaz)

sudo ./monitor.sh start wlan0
Sanal arayüz oluştur (wlan0 normal kalır, wlan0mon açılır)

sudo ./monitor.sh start wlan0 --new
Normale döndür

sudo ./monitor.sh stop wlan0mon
CLI (Komut Satırı) Modu
Tarama (5 GHz dahil)

sudo python3 SzrWifi.py -i wlan0mon scan -t 15 --all-channels -o apler.json
Deauth (Hedef kanalı otomatik ayarlar, Reason Code döngüsü kullanır)

sudo python3 SzrWifi.py -i wlan0mon deauth -b AA:BB:CC:DD:EE:FF -n 200
JSON'dan hedef seçerek deauth

sudo python3 SzrWifi.py -i wlan0mon deauth --from-json apler.json -b 2 --jitter 0.1
PMKID Yakalama (Clientless)

sudo python3 SzrWifi.py -i wlan0mon pmkid -b AA:BB:CC:DD:EE:FF -o pmkid.22000
TUI (İnteraktif Kabuk) Modu

Sadece --mitm parametresi eklendiğinde açılır. Modülleri module <isim> on/off komutlarıyla yönetebilirsiniz.

sudo python3 SzrWifi.py --mitm -i wlan0mon

Kabuk İçi Komutlar:

    modules -> Tüm modüllerin durumunu gösterir.

    module scan on -> Taramayı başlatır.

    module eapol on -> Handshake avcılığını başlatır.

    module mitm on <hedef_ip> <gateway_ip> -> ARP Spoof başlatır.

    module portal on <ssid> <sablon_adi> -> Captive Portal başlatır.

    save hs.22000 -> Yakalanan handshake'i hashcat formatında kaydeder.

    exit -> Çıkar (Tüm süreçleri ve ARP zehirlenmesini temizler).

📦 Modüller
Modül	Görev
scan	AP ve İstemcileri tarar, WPA3/PMF tespiti yapar.
eapol	M1+M2 eşleştirmesi yaparak hashcat için WPA*02* üretir.
deauth	Deauth / Disassoc saldırısı düzenler.
pmkid	İstemci gerektirmeden (clientless) PMKID yakalar (WPA*01*).
wps	reaver üzerinden Pixie Dust saldırısı başlatır.
portal	Evil Twin (Sahte AP) + Captive Portal (Oltalama) sunar.
mitm	ARP Spoofing ile aradaki adam (MITM) saldırısı yapar.
flood	Sahte Beacon paketleri ile ortalığı doldurur.
ids	Deauth saldırılarını tespit eden savunma modülü.
playbook	YAML dosyası ile otomatik saldırı zinciri çalıştırır.
📂 Klasör Yapısı

Szr-Wifi/
├── SzrWifi.py # Ana giriş noktası (CLI & REPL yönetimi)
├── monitor.sh # Wi-Fi kartı Monitor/Managed mod yöneticisi
├── banner.txt # Açılış ekranı (ASCII)
├── whitelist.txt # Saldırı yapılmayacak MAC adresleri
├── templates/ # Captive Portal HTML şablonları
├── playbooks/ # Otomasyon (YAML) dosyaları
└── szr/ # Çekirdek Python Modülleri
├── context.py # TUI, Sniffer ve Context sınıfları
├── dot11.py # 802.11 Paket Parse (Scapy)
├── iface.py # Arayüz işlemleri
└── modules/ # Saldırı ve Savunma Modülleri
👨‍💻 Geliştirici Notu

Bu proje, kağıt üzerindeki teorik bir koddan ziyade, gerçek saha koşullarında (Kali Linux, MTK MT7621 Wi-Fi çipleri, DFS kanalları ve sürücü inatlarıyla) test edilerek geliştirilmiştir. Özellikle DEVNULL hataları, Frekans/Kanal karmaşası ve 5 GHz DFS kanallarındaki enjeksiyon kilitleri pratik testlerle çözülmüştür.

Geliştirme & Debug Süreci: szr-kali
"Sadece yetkiniz olan sistemlerde kullanın!"
