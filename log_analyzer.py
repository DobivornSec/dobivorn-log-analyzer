#!/usr/bin/env python3
"""
Dobivorn Log Analyzer v2.0 🐉
3 Başlı Ejderha | Red Team | Purple Team | Blue Team

Özellikler:
- Apache/Nginx log analizi
- Gerçek zamanlı log izleme (tail -f)
- Coğrafi IP analizi (ülke/şehir)
- Anomali tespiti (brute-force, scan)
- HTML/JSON/CSV raporlama
- Bot/scanner tespiti
"""

import re
import sys
import json
import csv
import argparse
import time
import requests
from collections import Counter, defaultdict
from datetime import datetime
from colorama import init, Fore, Style
import threading
import os
import signal

# Renkleri başlat
init(autoreset=True)

# Banner
BANNER = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════════╗
║   🐉 Dobivorn Log Analyzer v2.0 - 3 Başlı Ejderha            ║
║   🔴 Red Team | 🟣 Purple Team | 🔵 Blue Team                ║
║   📊 Real-time | 🌍 GeoIP | 📈 HTML Report | 🚨 Anomaly      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Bot/Scanner tespiti için kalıplar
BOT_PATTERNS = ['bot', 'spider', 'crawler', 'scanner', 'nmap', 'curl', 'wget', 'python', 'go-http-client']
ATTACK_PATTERNS = [
    ('wp-admin', 'WordPress brute-force'),
    ('xmlrpc.php', 'XML-RPC attack'),
    ('.env', 'Environment file access'),
    ('backup.zip', 'Backup file access'),
    ('phpmyadmin', 'phpMyAdmin access'),
    ('sqlmap', 'SQLMap detected'),
    ('/../', 'Path traversal'),
    ('union select', 'SQL injection'),
]

class DobivornLogAnalyzer:
    def __init__(self, log_file, top_n=10, realtime=False, geoip=False, html_report=None):
        self.log_file = log_file
        self.top_n = top_n
        self.realtime = realtime
        self.geoip = geoip
        self.html_report = html_report
        self.stats = {
            'total_requests': 0,
            'unique_ips': set(),
            'ip_count': Counter(),
            'url_count': Counter(),
            'status_count': Counter(),
            'hour_count': Counter(),
            'method_count': Counter(),
            'bot_count': 0,
            'attacks': Counter(),
            'errors': []
        }
        self.ip_cache = {}  # IP geo cache
        self.running = True
        
    def get_ip_location(self, ip):
        """IP adresinin coğrafi konumunu al"""
        if not self.geoip:
            return None
        
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0)
                    }
                    self.ip_cache[ip] = location
                    return location
        except:
            pass
        
        self.ip_cache[ip] = None
        return None
    
    def parse_log_line(self, line):
        """Apache/Nginx log satırını ayrıştır"""
        # Apache combined log format
        pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
        match = re.match(pattern, line)
        
        if match:
            ip = match.group(1)
            time_str = match.group(2)
            method = match.group(3)
            url = match.group(4)
            status = int(match.group(6))
            
            # Zaman parse
            try:
                time_obj = datetime.strptime(time_str[:20], "%d/%b/%Y:%H:%M:%S")
                hour = time_obj.hour
                date = time_obj.strftime("%Y-%m-%d")
            except:
                hour = 0
                date = "Unknown"
            
            return {
                'ip': ip,
                'hour': hour,
                'date': date,
                'method': method,
                'url': url,
                'status': status
            }
        return None
    
    def detect_attack(self, url, user_agent_line):
        """Saldırı tespiti yap"""
        combined = (url + " " + user_agent_line).lower()
        for pattern, attack_type in ATTACK_PATTERNS:
            if pattern.lower() in combined:
                return attack_type
        return None
    
    def process_line(self, line, line_num=None):
        """Tek bir log satırını işle"""
        parsed = self.parse_log_line(line)
        if parsed:
            self.stats['total_requests'] += 1
            self.stats['unique_ips'].add(parsed['ip'])
            self.stats['ip_count'][parsed['ip']] += 1
            self.stats['url_count'][parsed['url']] += 1
            self.stats['status_count'][parsed['status']] += 1
            self.stats['hour_count'][parsed['hour']] += 1
            self.stats['method_count'][parsed['method']] += 1
            
            # Bot tespiti
            if any(bot in line.lower() for bot in BOT_PATTERNS):
                self.stats['bot_count'] += 1
            
            # Saldırı tespiti
            attack = self.detect_attack(parsed['url'], line)
            if attack:
                self.stats['attacks'][attack] += 1
                
            # Anomali tespiti (çok hızlı istekler)
            # Bu kısım real-time için özel
            return parsed
        else:
            if line_num:
                self.stats['errors'].append(f"Line {line_num}: {line[:50]}...")
        return None
    
    def analyze_file(self):
        """Log dosyasını analiz et"""
        print(f"{Fore.YELLOW}[+] Log dosyası: {self.log_file}{Style.RESET_ALL}")
        print(f"[+] Analiz başlıyor...\n")
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    self.process_line(line, line_num)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Dosya bulunamadı: {self.log_file}{Style.RESET_ALL}")
            sys.exit(1)
    
    def realtime_tail(self):
        """Gerçek zamanlı log izleme (tail -f gibi)"""
        print(f"{Fore.GREEN}[+] Gerçek zamanlı izleme başladı: {self.log_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        # Dosya boyutunu al
        with open(self.log_file, 'r') as f:
            f.seek(0, os.SEEK_END)
            last_position = f.tell()
        
        try:
            while self.running:
                with open(self.log_file, 'r') as f:
                    f.seek(last_position)
                    for line in f:
                        parsed = self.process_line(line)
                        if parsed:
                            # Yeni isteği göster
                            print(f"{Fore.GREEN}[+] {parsed['ip']} -> {parsed['method']} {parsed['url']} ({parsed['status']}){Style.RESET_ALL}")
                            
                            # Anomali uyarısı
                            if parsed['status'] == 404:
                                print(f"{Fore.YELLOW}  ⚠️  404 Not Found{Style.RESET_ALL}")
                            elif parsed['status'] >= 500:
                                print(f"{Fore.RED}  🚨 Server Error!{Style.RESET_ALL}")
                    
                    last_position = f.tell()
                
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] İzleme durduruldu{Style.RESET_ALL}")
    
    def display_results(self):
        """Analiz sonuçlarını göster"""
        print(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    GENEL İSTATİSTİKLER                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Toplam istek: {self.stats['total_requests']}{Style.RESET_ALL}")
        print(f"[+] Benzersiz IP: {len(self.stats['unique_ips'])}")
        print(f"[+] Bot/Scanner tespiti: {self.stats['bot_count']} (tahmini){Style.RESET_ALL}")
        
        if self.stats['attacks']:
            print(f"{Fore.RED}[!] Saldırı tespiti:{Style.RESET_ALL}")
            for attack, count in self.stats['attacks'].most_common():
                print(f"  → {attack}: {count} kez")
        
        # En çok istek yapan IP'ler
        print(f"\n{Fore.CYAN}📊 En Çok İstek Yapan IP'ler (Top {self.top_n}):{Style.RESET_ALL}")
        for ip, count in self.stats['ip_count'].most_common(self.top_n):
            location = self.get_ip_location(ip) if self.geoip else None
            loc_str = f" ({location['country']})" if location and location.get('country') else ""
            print(f"  → {ip}{loc_str}: {count} istek")
        
        # En çok ziyaret edilen URL'ler
        print(f"\n{Fore.CYAN}📊 En Çok Ziyaret Edilen URL'ler (Top {self.top_n}):{Style.RESET_ALL}")
        for url, count in self.stats['url_count'].most_common(self.top_n):
            display_url = url[:60] + "..." if len(url) > 60 else url
            print(f"  → {display_url}: {count} istek")
        
        # HTTP Durum kodları
        print(f"\n{Fore.CYAN}📊 HTTP Durum Kodları:{Style.RESET_ALL}")
        for status in sorted(self.stats['status_count'].keys()):
            count = self.stats['status_count'][status]
            if status >= 500:
                color = Fore.RED
            elif status >= 400:
                color = Fore.YELLOW
            else:
                color = Fore.GREEN
            print(f"  {color}→ {status}: {count} istek{Style.RESET_ALL}")
        
        # Coğrafi dağılım (varsa)
        if self.geoip and self.ip_cache:
            geo_counter = Counter()
            for ip in self.stats['unique_ips']:
                if ip in self.ip_cache and self.ip_cache[ip]:
                    geo_counter[self.ip_cache[ip].get('country', 'Unknown')] += 1
            
            if geo_counter:
                print(f"\n{Fore.CYAN}📊 Coğrafi Dağılım (Top 5):{Style.RESET_ALL}")
                for country, count in geo_counter.most_common(5):
                    print(f"  → {country}: {count} IP")
    
    def generate_html_report(self):
        """HTML rapor oluştur"""
        if not self.html_report:
            return
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dobivorn Log Analyzer Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #3498db; border-bottom: 2px solid #3498db; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background: #ecf0f1; padding: 15px; border-radius: 8px; text-align: center; }}
        .card h3 {{ margin: 0; color: #2c3e50; }}
        .card p {{ font-size: 24px; font-weight: bold; margin: 10px 0 0; color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .attack {{ background: #ffe6e6; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🐉 Dobivorn Log Analyzer Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Log File: {self.log_file}</p>
        
        <div class="stats">
            <div class="card"><h3>Total Requests</h3><p>{self.stats['total_requests']}</p></div>
            <div class="card"><h3>Unique IPs</h3><p>{len(self.stats['unique_ips'])}</p></div>
            <div class="card"><h3>Bot Requests</h3><p>{self.stats['bot_count']}</p></div>
            <div class="card"><h3>Attacks Detected</h3><p>{sum(self.stats['attacks'].values())}</p></div>
        </div>
        
        <h2>📊 Top IPs</h2>
        <table>
            <tr><th>IP Address</th><th>Requests</th></tr>
            {''.join(f'<tr><td>{ip}</td><td>{count}</td></tr>' for ip, count in self.stats['ip_count'].most_common(10))}
        </table>
        
        <h2>📊 Top URLs</h2>
        <table>
            <tr><th>URL</th><th>Requests</th></tr>
            {''.join(f'<tr><td>{url[:80]}</td><td>{count}</td></tr>' for url, count in self.stats['url_count'].most_common(10))}
        </table>
        
        <h2>📊 Status Codes</h2>
        <table>
            <tr><th>Status</th><th>Count</th></tr>
            {''.join(f'<tr><td>{status}</td><td>{count}</td></tr>' for status, count in sorted(self.stats['status_count'].items()))}
        </table>
        
        <h2>🚨 Attacks Detected</h2>
        <table>
            <tr><th>Attack Type</th><th>Count</th></tr>
            {''.join(f'<tr class="attack"><td>{attack}</td><td>{count}</td></tr>' for attack, count in self.stats['attacks'].most_common()) if self.stats['attacks'] else '<tr><td colspan="2">No attacks detected</td></tr>'}
        </table>
    </div>
</body>
</html>"""
        
        with open(self.html_report, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML raporu kaydedildi: {self.html_report}{Style.RESET_ALL}")
    
    def export_json(self, output_file):
        """JSON çıktısı"""
        export_data = {
            'summary': {
                'total_requests': self.stats['total_requests'],
                'unique_ips': len(self.stats['unique_ips']),
                'bot_requests': self.stats['bot_count']
            },
            'top_ips': [{'ip': ip, 'count': count} for ip, count in self.stats['ip_count'].most_common(self.top_n)],
            'top_urls': [{'url': url, 'count': count} for url, count in self.stats['url_count'].most_common(self.top_n)],
            'status_codes': dict(self.stats['status_count']),
            'hourly_distribution': dict(self.stats['hour_count']),
            'attacks': dict(self.stats['attacks'])
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        print(f"{Fore.GREEN}[+] JSON çıktısı kaydedildi: {output_file}{Style.RESET_ALL}")
    
    def export_csv(self, output_file):
        """CSV çıktısı"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Rapor Türü', 'Veri'])
            writer.writerow(['Toplam İstek', self.stats['total_requests']])
            writer.writerow(['Benzersiz IP', len(self.stats['unique_ips'])])
            writer.writerow(['Bot İstekleri', self.stats['bot_count']])
            writer.writerow([])
            writer.writerow(['Top IP\'ler (IP,İstek Sayısı)'])
            for ip, count in self.stats['ip_count'].most_common(self.top_n):
                writer.writerow([ip, count])
            writer.writerow([])
            writer.writerow(['Top URL\'ler (URL,İstek Sayısı)'])
            for url, count in self.stats['url_count'].most_common(self.top_n):
                writer.writerow([url, count])
        
        print(f"{Fore.GREEN}[+] CSV çıktısı kaydedildi: {output_file}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="Dobivorn Log Analyzer v2.0 - Web Server Log Analiz Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python log_analyzer.py access.log
  python log_analyzer.py access.log -n 20
  python log_analyzer.py access.log --realtime
  python log_analyzer.py access.log --geoip -o rapor.json
  python log_analyzer.py access.log --html rapor.html
        """
    )
    
    parser.add_argument("log_file", help="Log dosyası yolu")
    parser.add_argument("-n", "--top", type=int, default=10, help="Gösterilecek top N (varsayılan: 10)")
    parser.add_argument("-j", "--json", help="JSON çıktı dosyası")
    parser.add_argument("-c", "--csv", help="CSV çıktı dosyası")
    parser.add_argument("--html", help="HTML rapor dosyası")
    parser.add_argument("--realtime", action="store_true", help="Gerçek zamanlı log izleme (tail -f)")
    parser.add_argument("--geoip", action="store_true", help="Coğrafi IP analizi (internet bağlantısı gerekir)")
    
    args = parser.parse_args()
    
    print(BANNER)
    
    analyzer = DobivornLogAnalyzer(
        log_file=args.log_file,
        top_n=args.top,
        realtime=args.realtime,
        geoip=args.geoip,
        html_report=args.html
    )
    
    if args.realtime:
        analyzer.realtime_tail()
    else:
        analyzer.analyze_file()
        analyzer.display_results()
        
        if args.json:
            analyzer.export_json(args.json)
        if args.csv:
            analyzer.export_csv(args.csv)
        if args.html:
            analyzer.generate_html_report()
    
    print(f"\n{Fore.GREEN}[✓] Analiz tamamlandı!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
