# dobivorn-log-analyzer
Web server log dosyalarını analiz eden güçlü bir CLI aracı. Apache/Nginx log formatlarını destekler.

# Dobivorn Log Analyzer 📊

Web server log dosyalarını analiz eden güçlü bir CLI aracı. Apache/Nginx log formatlarını destekler.

## Özellikler

- 📊 Toplam istek ve benzersiz IP istatistikleri
- 🔝 En çok istek yapan IP'ler ve ziyaret edilen URL'ler
- 📈 HTTP durum kodu dağılımı (200, 403, 404, 500 vs.)
- ⏰ Saat bazında istek yoğunluğu
- 🤖 Basit bot/scanner tespiti
- 💾 JSON / CSV çıktı desteği

## Kurulum

    git clone https://github.com/DobivornSec/dobivorn-log-analyzer.git
    cd dobivorn-log-analyzer

# requirements.txt gerekmez, pure Python

## Kullanım

# Temel analiz
    python3 log_analyzer.py access.log

# Top 20 göster
    python3 log_analyzer.py access.log -n 20

# JSON çıktısı
    python3 log_analyzer.py access.log -j rapor.json

# CSV çıktısı
    python3 log_analyzer.py access.log -c rapor.csv

## Örnek Çıktı

    📊 En Çok İstek Yapan IP'ler:
    → 192.168.1.100: 1542 istek
    → 192.168.1.101: 892 istek

    📊 HTTP Durum Kodları:
    → 200: 5234 istek
    → 404: 342 istek
    → 403: 123 istek

Desteklenen Log Formatları

    Apache Combined Log Format

    Nginx Default Log Format

Yapılacaklar

    Gerçek zamanlı log izleme (tail -f benzeri)

    Anomali tespiti (basit)

    Coğrafi IP analizi

    Görsel rapor (HTML)
