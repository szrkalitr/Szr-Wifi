import subprocess

def _run(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def kurallari_ekle(iface):
    _run("echo 1 > /proc/sys/net/ipv4/ip_forward")
    _run("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    _run("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    
    _run(f"iptables -t nat -A PREROUTING -i {iface} -p udp --dport 53 -j DNAT --to-destination 10.0.0.1:53")
    _run(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80")
    _run(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80")
    
    _run(f"iptables -A FORWARD -i {iface} -p tcp --dport 853 -j REJECT")
    _run(f"iptables -A FORWARD -i {iface} -p udp --dport 853 -j REJECT")
    _run(f"iptables -A FORWARD -i {iface} -p tcp --dport 443 -j REJECT")

def temizle(iface):
    _run("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
    _run("sysctl -w net.ipv6.conf.default.disable_ipv6=0")
    _run(f"iptables -t nat -D PREROUTING -i {iface} -p udp --dport 53 -j DNAT --to-destination 10.0.0.1:53 2>/dev/null")
    _run(f"iptables -t nat -D PREROUTING -i {iface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80 2>/dev/null")
    _run(f"iptables -t nat -D PREROUTING -i {iface} -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80 2>/dev/null")
    _run(f"iptables -D FORWARD -i {iface} -p tcp --dport 853 -j REJECT 2>/dev/null")
    _run(f"iptables -D FORWARD -i {iface} -p udp --dport 853 -j REJECT 2>/dev/null")
    _run(f"iptables -D FORWARD -i {iface} -p tcp --dport 443 -j REJECT 2>/dev/null")
