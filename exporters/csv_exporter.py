"""CSV export support."""

import csv


def export_csv(stats: dict, top_n: int, output_file: str) -> None:
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Report Type", "Data"])
        writer.writerow(["Total Requests", stats["total_requests"]])
        writer.writerow(["Unique IPs", len(stats["unique_ips"])])
        writer.writerow(["Bot Requests", stats["bot_count"]])
        writer.writerow([])

        writer.writerow(["Top IPs (IP, Count)"])
        for ip, count in stats["ip_count"].most_common(top_n):
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Top URLs (URL, Count)"])
        for url, count in stats["url_count"].most_common(top_n):
            writer.writerow([url, count])
