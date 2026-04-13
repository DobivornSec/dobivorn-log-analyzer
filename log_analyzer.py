#!/usr/bin/env python3
import re
import sys
import json
import argparse
from collections import Counter
from datetime import datetime
import os

# Renk kodları
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

def banner():
    print(f"""
{BLUE}╔══════════════════════════════════════════╗
║   Dobivorn Log Analyzer 📊                ║
║   Web Server Log Analiz Aracı             ║
╚══════════════════════════════════════════╝{RESET}
    """)

def parse_log_line(line):
    """Apache/Nginx log satırını ayrıştırır"""
    # Apache combined log format regex
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
    match = re.match(pattern, line)
    
    if match:
        ip = match.group(1)
        time_str = match.group(2)
        method = match.group(3)
        url = match.group(4)
        protocol = match.group(5)
        status = int(match.group(6))
        size = match.group(7)
        
        # Zamanı parse et
        try:
            # 14/Apr/2026:12:45:23 +0300 formatını parse et
            time_obj = datetime.strptime(time_str[:20], "%d/%b/%Y:%H:%M:%S")
            hour = time_obj.hour
        except:
            hour = 0
        
        return {
            'ip': ip,
            'time': time_str,
            'hour': hour,
            'method': method,
            'url': url,
            'protocol': protocol,
            'status': status,
            'size': size
        }
    return None

def is_bot(user_agent):
    """Basit bot tespiti (user-agent'a göre)"""
    bots = ['bot', 'spider', 'crawler', 'scanner', 'nmap', 'curl', 'wget', 'python', 'go-http-client']
    return any(bot in user_agent.lower() for bot in bots)

def analyze_log_file(log_file, top_n=10):
    """Log dosyasını analiz eder"""
    print(f"{YELLOW}[+] Log dosyası: {log_file}{RESET}")
    print(f"[+] Analiz başlıyor...\n")
    
    stats = {
        'total_requests': 0,
        'unique_ips': set(),
        'ip_count': Counter(),
        'url_count': Counter(),
        'status_count': Counter(),
        'hour_count': Counter(),
        'bot_count': 0,
        'errors': []
    }
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    stats['total_requests'] += 1
                    stats['unique_ips'].add(parsed['ip'])
                    stats['ip_count'][parsed['ip']] += 1
                    stats['url_count'][parsed['url']] += 1
                    stats['status_count'][parsed['status']] += 1
                    stats['hour_count'][parsed['hour']] += 1
                    
                    # Bot tespiti (basit - sadece user-agent içeriyorsa)
                    if 'bot' in line.lower() or 'spider' in line.lower():
                        stats['bot_count'] += 1
                else:
                    stats['errors'].append(line[:50] + "...")
    except FileNotFoundError:
        print(f"{RED}[!] Dosya bulunamadı: {log_file}{RESET}")
        sys.exit(1)
    
    return stats

def display_results(stats, top_n):
    """Analiz sonuçlarını gösterir"""
    print(f"{BLUE}╔══════════════════════════════════════════╗")
    print(f"║              GENEL İSTATİSTİKLER           ║")
    print(f"╚══════════════════════════════════════════╝{RESET}")
    
    print(f"{GREEN}[+] Toplam istek: {stats['total_requests']}{RESET}")
    print(f"[+] Benzersiz IP: {len(stats['unique_ips'])}")
    print(f"[+] Bot/Scanner tespiti: {stats['bot_count']} (tahmini){RESET}\n")
    
    # En çok istek yapan IP'ler
    print(f"{CYAN}📊 En Çok İstek Yapan IP'ler (Top {top_n}):{RESET}")
    for ip, count in stats['ip_count'].most_common(top_n):
        print(f"  → {ip}: {count} istek")
    
    # En çok ziyaret edilen URL'ler
    print(f"\n{CYAN}📊 En Çok Ziyaret Edilen URL'ler (Top {top_n}):{RESET}")
    for url, count in stats['url_count'].most_common(top_n):
        # URL'i kısalt (çok uzunsa)
        display_url = url[:60] + "..." if len(url) > 60 else url
        print(f"  → {display_url}: {count} istek")
    
    # HTTP Durum kodları
    print(f"\n{CYAN}📊 HTTP Durum Kodları:{RESET}")
    for status in sorted(stats['status_count'].keys()):
        count = stats['status_count'][status]
        if status >= 500:
            color = RED
        elif status >= 400:
            color = YELLOW
        else:
            color = GREEN
        print(f"  {color}→ {status}: {count} istek{RESET}")
    
    # Saat bazında dağılım
    print(f"\n{CYAN}📊 Saat Bazında İstek Dağılımı:{RESET}")
    for hour in range(0, 24):
        count = stats['hour_count'].get(hour, 0)
        bar = '█' * min(count // max(1, stats['total_requests'] // 40), 40)
        if count > 0:
            print(f"  {hour:02d}:00 → {bar} ({count})")
    
    # Hatalar (parse edilemeyen satırlar)
    if stats['errors'] and len(stats['errors']) > 0:
        print(f"\n{YELLOW}⚠️  {len(stats['errors'])} satır parse edilemedi (format uyumsuz){RESET}")

def export_json(stats, output_file, top_n):
    """Sonuçları JSON dosyasına kaydeder"""
    export_data = {
        'summary': {
            'total_requests': stats['total_requests'],
            'unique_ips': len(stats['unique_ips']),
            'bot_requests': stats['bot_count']
        },
        'top_ips': [{'ip': ip, 'count': count} for ip, count in stats['ip_count'].most_common(top_n)],
        'top_urls': [{'url': url, 'count': count} for url, count in stats['url_count'].most_common(top_n)],
        'status_codes': dict(stats['status_count']),
        'hourly_distribution': dict(stats['hour_count'])
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n{GREEN}[✓] JSON çıktısı kaydedildi: {output_file}{RESET}")

def export_csv(stats, output_file, top_n):
    """Sonuçları CSV dosyasına kaydeder (basit)"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Rapor Türü,Veri\n")
        f.write(f"Toplam İstek,{stats['total_requests']}\n")
        f.write(f"Benzersiz IP,{len(stats['unique_ips'])}\n")
        f.write(f"Bot İstekleri,{stats['bot_count']}\n\n")
        
        f.write("Top IP'ler (IP,İstek Sayısı)\n")
        for ip, count in stats['ip_count'].most_common(top_n):
            f.write(f"{ip},{count}\n")
        
        f.write("\nTop URL'ler (URL,İstek Sayısı)\n")
        for url, count in stats['url_count'].most_common(top_n):
            f.write(f"{url},{count}\n")
        
        f.write("\nHTTP Durum Kodları (Kod,Sayı)\n")
        for status, count in stats['status_count'].items():
            f.write(f"{status},{count}\n")
    
    print(f"\n{GREEN}[✓] CSV çıktısı kaydedildi: {output_file}{RESET}")

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="Dobivorn Log Analyzer - Web Server Log Analiz Aracı")
    parser.add_argument("log_file", help="Log dosyası yolu (Apache/Nginx formatı)")
    parser.add_argument("-n", "--top", type=int, default=10, help="Gösterilecek top N sayısı (varsayılan: 10)")
    parser.add_argument("-j", "--json", help="Sonuçları JSON dosyasına kaydet")
    parser.add_argument("-c", "--csv", help="Sonuçları CSV dosyasına kaydet")
    
    args = parser.parse_args()
    
    # Log dosyasını analiz et
    stats = analyze_log_file(args.log_file, args.top)
    
    # Sonuçları göster
    display_results(stats, args.top)
    
    # İsteğe bağlı çıktılar
    if args.json:
        export_json(stats, args.json, args.top)
    
    if args.csv:
        export_csv(stats, args.csv, args.top)
    
    print(f"\n{GREEN}[✓] Analiz tamamlandı!{RESET}")

if __name__ == "__main__":
    main()
