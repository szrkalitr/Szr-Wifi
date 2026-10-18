#!/usr/bin/env bash

set -o pipefail

R=$'\033[0m'; G=$'\033[32m'; Y=$'\033[33m'; E=$'\033[31m'; C=$'\033[36m'
info() { echo -e "${C}[*]${R} $*"; }
ok()   { echo -e "${G}[+]${R} $*"; }
warn() { echo -e "${Y}[!]${R} $*"; }
err()  { echo -e "${E}[-]${R} $*"; }

root_kontrol() {
    if [[ $EUID -ne 0 ]]; then
        err "Root gerekli: sudo $0 $*"
        exit 1
    fi
}

arayuz_var_mi() { ip link show "$1" &>/dev/null; }

arayuz_tipi() {
    iw dev "$1" info 2>/dev/null | awk '/type/ {print $2; exit}'
}

phy_bul() {
    iw dev "$1" info 2>/dev/null | awk '/wiphy/ {print "phy"$2; exit}'
}

nm_unmanage() {
    local iface="$1"
    if command -v nmcli &>/dev/null; then
        nmcli device set "$iface" managed no 2>/dev/null || true
    fi
}

nm_manage() {
    local iface="$1"
    if command -v nmcli &>/dev/null; then
        nmcli device set "$iface" managed yes 2>/dev/null || true
    fi
}

wpa_oldur() {
    local iface="$1"
    pkill -f "wpa_supplicant.*$iface" 2>/dev/null || true
    pkill -f "dhclient.*$iface"        2>/dev/null || true
}

monitor_baslat() {
    local iface="$1"
    local mod="${2:-type}"
    local yeni_ad="$3"

    root_kontrol "start $iface"

    if ! arayuz_var_mi "$iface"; then
        err "Arayuz yok: $iface"
        info "Mevcut arayuzler:"
        iw dev | grep Interface
        exit 1
    fi

    local mevcut; mevcut=$(arayuz_tipi "$iface")
    if [[ "$mevcut" == "monitor" ]]; then
        warn "$iface zaten monitor modda"
        exit 0
    fi

    if [[ "$mod" == "new" ]]; then
        local phy; phy=$(phy_bul "$iface")
        if [[ -z "$phy" ]]; then
            err "PHY bulunamadi: $iface"
            exit 1
        fi
        local yeni="${yeni_ad:-${iface}mon}"
        if arayuz_var_mi "$yeni"; then
            err "$yeni zaten var, once stop et"
            exit 1
        fi
        info "Yeni monitor arayuz: $yeni ($phy)"
        iw phy "$phy" interface add "$yeni" type monitor || {
            err "iw interface add basarisiz"
            exit 1
        }
        ip link set "$yeni" up
        ok "Hazir: $yeni (monitor) — $iface managed kaldi"
    else
        info "$iface -> monitor (mevcut arayuz degistiriliyor)"
        nm_unmanage "$iface"
        wpa_oldur "$iface"
        ip link set "$iface" down
        iw dev "$iface" set type monitor || {
            err "iw set type monitor basarisiz"
            ip link set "$iface" up
            nm_manage "$iface"
            exit 1
        }
        ip link set "$iface" up
        ok "Hazir: $iface (monitor)"
    fi
}

monitor_durdur() {
    local iface="$1"
    root_kontrol "stop $iface"

    if ! arayuz_var_mi "$iface"; then
        err "Arayuz yok: $iface"
        exit 1
    fi

    local tip; tip=$(arayuz_tipi "$iface")
    if [[ "$tip" != "monitor" ]]; then
        warn "$iface zaten monitor modda degil (tip=$tip)"
        exit 0
    fi

    if [[ "$iface" == *mon ]]; then
        info "$iface siliniyor (ayri monitor arayuz)"
        ip link set "$iface" down 2>/dev/null || true
        iw dev "$iface" del 2>/dev/null && {
            ok "$iface kaldirildi"
            exit 0
        }
        warn "iw dev del basarisiz, managed'a cevriliyor"
    fi

    info "$iface -> managed"
    ip link set "$iface" down
    iw dev "$iface" set type managed || {
        err "iw set type managed basarisiz"
        ip link set "$iface" up
        exit 1
    }
    ip link set "$iface" up
    nm_manage "$iface"
    ok "Hazir: $iface (managed)"
}

durum_goster() {
    local iface="${1:-}"
    if [[ -n "$iface" ]]; then
        iw dev "$iface" info 2>/dev/null || {
            err "Arayuz yok: $iface"
            exit 1
        }
        return
    fi
    info "Kablosuz arayuzler:"
    printf "%-15s %-10s %-10s %-8s\n" "IFACE" "TYPE" "PHY" "CH"
    printf "%-15s %-10s %-10s %-8s\n" "-----" "----" "---" "--"
    while IFS= read -r line; do
        local i; i=$(echo "$line" | awk '/Interface/ {print $2}')
        [[ -z "$i" ]] && continue
        local t; t=$(arayuz_tipi "$i")
        local p; p=$(phy_bul "$i")
        local ch; ch=$(iw dev "$i" info 2>/dev/null | awk '/channel/ {print $2; exit}')
        printf "%-15s %-10s %-10s %-8s\n" "$i" "${t:-?}" "${p:-?}" "${ch:--}"
    done < <(iw dev)
}

menu() {
    while true; do
        echo
        echo "  Szr-Wifi Monitor Yardimcisi"
        echo "  ---------------------------"
        echo "  1) Monitor moda al (mevcut arayuz)"
        echo "  2) Monitor moda al (yeni arayuz olustur)"
        echo "  3) Managed moda al"
        echo "  4) Durum goster"
        echo "  5) Cikis"
        echo
        read -rp "Secim [1-5]: " sec

        case "$sec" in
            1)
                read -rp "Arayuz (varsayilan wlan0): " i
                monitor_baslat "${i:-wlan0}" type
                ;;
            2)
                read -rp "Kaynak arayuz (varsayilan wlan0): " i
                i="${i:-wlan0}"
                read -rp "Yeni ad (varsayilan ${i}mon): " n
                monitor_baslat "$i" new "${n:-${i}mon}"
                ;;
            3)
                read -rp "Arayuz (varsayilan wlan0mon): " i
                monitor_durdur "${i:-wlan0mon}"
                ;;
            4) durum_goster ;;
            5) ok "Cikiliyor"; exit 0 ;;
            *) err "Gecersiz secim" ;;
        esac
    done
}

case "${1:-}" in
    start)
        shift
        MODE="type"; NAME=""
        IFACE=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --new)  MODE="new"; shift ;;
                --name) NAME="$2"; shift 2 ;;
                -*)     err "Bilinmeyen secenek: $1"; exit 1 ;;
                *)      IFACE="$1"; shift ;;
            esac
        done
        monitor_baslat "${IFACE:-wlan0}" "$MODE" "$NAME"
        ;;
    stop)
        monitor_durdur "${2:-wlan0mon}"
        ;;
    status)
        durum_goster "${2:-}"
        ;;
    ""|menu)
        menu
        ;;
    -h|--help|help)
        cat <<EOF
Kullanim:
  sudo $0 start [iface] [--new] [--name AD]
      --new            ayri monitor arayuz olustur (mevcut managed kalir)
      --name AD        --new ile kullanilir; arayuz adi (varsayilan iface+"mon")

  sudo $0 stop  [iface]   managed'a cevir (veya ayri mon arayuzu sil)
       $0 status [iface]  durum goster
       $0 menu            interaktif menu

Ornekler:
  sudo $0 start wlan0                 # wlan0 -> monitor
  sudo $0 start wlan0 --new           # wlan0mon olustur, wlan0 managed
  sudo $0 start wlan0 --new --name mon0
  sudo $0 stop wlan0mon               # managed'a don / sil
EOF
        ;;
    *)
        err "Bilinmeyen komut: $1"
        echo "Yardim: $0 -h"
        exit 1
        ;;
esac
