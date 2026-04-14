# 🐉 Dobivorn Log Analyzer v2.0

> **3 Başlı Ejderha** | Red Team | Purple Team | Blue Team

Web server log dosyalarını analiz eden **profesyonel** bir CLI aracı. Apache/Nginx log formatlarını destekler. Gerçek zamanlı izleme, coğrafi IP analizi, saldırı tespiti ve HTML raporlama ile donatılmıştır.

---

## ✨ Özellikler

| Özellik | Açıklama |
|---------|----------|
| 📊 **İstatistikler** | Toplam istek, benzersiz IP, bot tespiti |
| 🔝 **Top Listeler** | En çok istek yapan IP'ler ve URL'ler |
| 📈 **HTTP Durum Kodları** | 200, 403, 404, 500 dağılımı |
| ⏰ **Saat Bazında** | İstek yoğunluğu analizi |
| 🤖 **Bot/Scanner Tespiti** | curl, wget, python, nmap vb. |
| 🚨 **Saldırı Tespiti** | WordPress brute-force, SQL injection, path traversal |
| 🌍 **Coğrafi IP Analizi** | Ülke/şehir bazında dağılım (IP-API) |
| 📡 **Gerçek Zamanlı İzleme** | `tail -f` benzeri canlı log takibi |
| 📊 **HTML Rapor** | Görsel ve interaktif rapor |
| 💾 **JSON/CSV Çıktı** | Yapılandırılmış veri çıktısı |

---

## 📦 Kurulum

```bash
git clone https://github.com/DobivornSec/dobivorn-log-analyzer.git
cd dobivorn-log-analyzer
pip install -r requirements.txt
```

**Gereksinimler:**
```bash
pip install requests colorama
```

---

## 🚀 Kullanım

### Temel analiz
```bash
python log_analyzer.py access.log
```

### Top N göster
```bash
python log_analyzer.py access.log -n 20
```

### JSON çıktısı
```bash
python log_analyzer.py access.log -j rapor.json
```

### CSV çıktısı
```bash
python log_analyzer.py access.log -c rapor.csv
```

### Gerçek zamanlı izleme (tail -f)
```bash
python log_analyzer.py access.log --realtime
```

### Coğrafi IP analizi (internet gerekir)
```bash
python log_analyzer.py access.log --geoip
```

### HTML rapor oluşturma
```bash
python log_analyzer.py access.log --html rapor.html
```

### Tüm özellikler bir arada
```bash
python log_analyzer.py access.log --geoip -j rapor.json --html rapor.html -n 15
```

---

## 📊 Örnek Çıktı

```bash
╔══════════════════════════════════════════════════════════════╗
║   🐉 Dobivorn Log Analyzer v2.0 - 3 Başlı Ejderha            ║
║   🔴 Red Team | 🟣 Purple Team | 🔵 Blue Team                ║
║   📊 Real-time | 🌍 GeoIP | 📈 HTML Report | 🚨 Anomaly      ║
╚══════════════════════════════════════════════════════════════╝

[+] Log dosyası: access.log
[+] Analiz başlıyor...

╔══════════════════════════════════════════════════════════════╗
║                    GENEL İSTATİSTİKLER                      ║
╚══════════════════════════════════════════════════════════════╝
[+] Toplam istek: 1542
[+] Benzersiz IP: 342
[+] Bot/Scanner tespiti: 89 (tahmini)

[!] Saldırı tespiti:
  → WordPress brute-force: 23 kez
  → Backup file access: 12 kez

📊 En Çok İstek Yapan IP'ler (Top 10):
  → 192.168.1.100 (Turkey): 1542 istek
  → 192.168.1.101 (Germany): 892 istek

📊 En Çok Ziyaret Edilen URL'ler (Top 10):
  → /index.html: 523 istek
  → /login.php: 342 istek
  → /wp-admin/admin-ajax.php: 123 istek

📊 HTTP Durum Kodları:
  → 200: 5234 istek
  → 404: 342 istek
  → 403: 123 istek
  → 500: 45 istek

📊 Coğrafi Dağılım (Top 5):
  → Turkey: 45 IP
  → Germany: 32 IP
  → United States: 28 IP
  → Netherlands: 15 IP
  → Russia: 8 IP

[✓] Analiz tamamlandı!
```

---

## 🔧 Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `log_file` | Log dosyası yolu | Zorunlu |
| `-n, --top` | Gösterilecek top N sayısı | 10 |
| `-j, --json` | JSON çıktı dosyası | Yok |
| `-c, --csv` | CSV çıktı dosyası | Yok |
| `--html` | HTML rapor dosyası | Yok |
| `--realtime` | Gerçek zamanlı izleme | Kapalı |
| `--geoip` | Coğrafi IP analizi | Kapalı |

---

## 📁 Desteklenen Log Formatları

| Format | Açıklama |
|--------|----------|
| **Apache Combined** | `%h %l %u %t "%r" %>s %b` |
| **Nginx Default** | `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent` |

---

## 🚨 Tespit Edilen Saldırı Türleri

| Saldırı | Açıklama |
|---------|----------|
| **WordPress brute-force** | wp-admin, xmlrpc.php saldırıları |
| **Backup file access** | .bak, .sql, .zip erişimleri |
| **Path traversal** | `../` dizin geçiş saldırıları |
| **SQL injection** | `union select`, `' or '1'='1` |

---

## 📊 HTML Rapor Örneği

HTML raporu tarayıcıda açtığında şunları içerir:
- Toplam istek, benzersiz IP, bot sayısı
- En çok istek yapan IP'ler (tablo)
- En çok ziyaret edilen URL'ler (tablo)
- HTTP durum kodları dağılımı
- Tespit edilen saldırılar

---

## ⚠️ Uyarı

> Bu araç **eğitim ve yetkili testler** için geliştirilmiştir. Log dosyalarını analiz ederken gizlilik ve yasal düzenlemelere uyunuz.

## ⭐ Star Atmayı Unutma!

Beğendiysen GitHub'da ⭐ bırakmayı unutma!
