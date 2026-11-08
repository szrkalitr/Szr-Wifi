import subprocess
import os

ENGINE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "flood_engine", "target", "release", "flood_engine"
)

def flood_attack(iface, rate=0, count=0, channel=None, ssid_prefix="fake"):
    if not os.path.exists(ENGINE_PATH):
        print(f"Rust motoru bulunamadı: {ENGINE_PATH}")
        return

    cmd = [
        ENGINE_PATH,
        "-i", iface,
        "-c", str(count),
        "-s", ssid_prefix,
    ]
    
    if rate > 0:
        cmd.extend(["-r", str(rate)])

    if channel is not None:
        cmd.extend(["--channel", str(channel)])

    print("Rust motoru çalıştırılıyor...")
    
    process = None
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        for line in process.stdout:
            print(line, end="", flush=True)
            
        process.wait()
        
        if process.returncode != 0:
            print(f"Motor hata verdi: {process.stderr.read()}")
            
    except KeyboardInterrupt:
        print("\nKullanıcı tarafından durduruldu.")
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            print("Motor kapatıldı.")

if __name__ == "__main__":
    flood_attack(iface="wlan0mon", rate=500, count=0, channel=36)
