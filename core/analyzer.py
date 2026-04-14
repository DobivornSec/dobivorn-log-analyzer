"""Main analysis workflow for Dobivorn Log Analyzer v3.0."""

from __future__ import annotations

import time
from collections import Counter

from colorama import Fore, Style, init

from core.constants import ATTACK_PATTERNS, BOT_PATTERNS
from core.parser import parse_log_line
from exporters.csv_exporter import export_csv
from exporters.html_exporter import generate_html_report
from exporters.json_exporter import export_json
from utils.geoip import GeoIPResolver

init(autoreset=True)


class DobivornLogAnalyzer:
    def __init__(self, log_file: str, top_n: int = 10, realtime: bool = False, geoip: bool = False) -> None:
        self.log_file = log_file
        self.top_n = top_n
        self.realtime = realtime
        self.geoip = GeoIPResolver(enabled=geoip)
        self.running = True
        self.stats = {
            "total_requests": 0,
            "unique_ips": set(),
            "ip_count": Counter(),
            "url_count": Counter(),
            "status_count": Counter(),
            "hour_count": Counter(),
            "method_count": Counter(),
            "bot_count": 0,
            "attacks": Counter(),
            "errors": [],
        }

    def detect_attack(self, url: str, user_agent_line: str) -> str | None:
        combined = (url + " " + user_agent_line).lower()
        for pattern, attack_type in ATTACK_PATTERNS:
            if pattern.lower() in combined:
                return attack_type
        return None

    def process_line(self, line: str, line_num: int | None = None) -> dict | None:
        parsed = parse_log_line(line)
        if not parsed:
            if line_num is not None:
                self.stats["errors"].append(f"Line {line_num}: {line[:50]}...")
            return None

        self.stats["total_requests"] += 1
        self.stats["unique_ips"].add(parsed["ip"])
        self.stats["ip_count"][parsed["ip"]] += 1
        self.stats["url_count"][parsed["url"]] += 1
        self.stats["status_count"][parsed["status"]] += 1
        self.stats["hour_count"][parsed["hour"]] += 1
        self.stats["method_count"][parsed["method"]] += 1

        if any(bot in line.lower() for bot in BOT_PATTERNS):
            self.stats["bot_count"] += 1

        attack = self.detect_attack(parsed["url"], line)
        if attack:
            self.stats["attacks"][attack] += 1

        return parsed

    def analyze_file(self) -> None:
        print(f"{Fore.YELLOW}[+] Log file: {self.log_file}{Style.RESET_ALL}")
        print("[+] Analysis started...\n")

        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    self.process_line(line, line_num)
        except FileNotFoundError:
            raise SystemExit(f"[!] File not found: {self.log_file}") from None

    def realtime_tail(self) -> None:
        print(f"{Fore.GREEN}[+] Realtime mode started: {self.log_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Press Ctrl+C to stop{Style.RESET_ALL}\n")

        with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            last_position = f.tell()

        try:
            while self.running:
                with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_position)
                    for line in f:
                        parsed = self.process_line(line)
                        if parsed:
                            print(
                                f"{Fore.GREEN}[+] {parsed['ip']} -> {parsed['method']} {parsed['url']} ({parsed['status']}){Style.RESET_ALL}"
                            )
                        if parsed and parsed["status"] == 404:
                            print(f"{Fore.YELLOW}  [!] 404 Not Found{Style.RESET_ALL}")
                        elif parsed and parsed["status"] >= 500:
                            print(f"{Fore.RED}  [!] Server Error{Style.RESET_ALL}")
                    last_position = f.tell()
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Realtime mode stopped{Style.RESET_ALL}")

    def display_results(self) -> None:
        print(f"\n{Fore.BLUE}===== GENERAL STATISTICS ====={Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total requests: {self.stats['total_requests']}{Style.RESET_ALL}")
        print(f"[+] Unique IPs: {len(self.stats['unique_ips'])}")
        print(f"[+] Bot/Scanner detections: {self.stats['bot_count']}")

        if self.stats["attacks"]:
            print(f"{Fore.RED}[!] Attack detections:{Style.RESET_ALL}")
            for attack, count in self.stats["attacks"].most_common():
                print(f"  -> {attack}: {count}")

        print(f"\n{Fore.CYAN}Top {self.top_n} IPs:{Style.RESET_ALL}")
        for ip, count in self.stats["ip_count"].most_common(self.top_n):
            location = self.geoip.get_location(ip)
            location_suffix = f" ({location['country']})" if location else ""
            print(f"  -> {ip}{location_suffix}: {count}")

        print(f"\n{Fore.CYAN}Top {self.top_n} URLs:{Style.RESET_ALL}")
        for url, count in self.stats["url_count"].most_common(self.top_n):
            display_url = url[:60] + "..." if len(url) > 60 else url
            print(f"  -> {display_url}: {count}")

        print(f"\n{Fore.CYAN}HTTP status codes:{Style.RESET_ALL}")
        for status in sorted(self.stats["status_count"].keys()):
            count = self.stats["status_count"][status]
            print(f"  -> {status}: {count}")

    def export_json(self, output_file: str) -> None:
        export_json(self.stats, self.top_n, output_file)
        print(f"{Fore.GREEN}[+] JSON saved: {output_file}{Style.RESET_ALL}")

    def export_csv(self, output_file: str) -> None:
        export_csv(self.stats, self.top_n, output_file)
        print(f"{Fore.GREEN}[+] CSV saved: {output_file}{Style.RESET_ALL}")

    def export_html(self, output_file: str) -> None:
        generate_html_report(self.stats, self.log_file, output_file)
        print(f"{Fore.GREEN}[+] HTML report saved: {output_file}{Style.RESET_ALL}")
