"""JSON export support."""

import json


def export_json(stats: dict, top_n: int, output_file: str) -> None:
    data = {
        "summary": {
            "total_requests": stats["total_requests"],
            "unique_ips": len(stats["unique_ips"]),
            "bot_requests": stats["bot_count"],
        },
        "top_ips": [
            {"ip": ip, "count": count}
            for ip, count in stats["ip_count"].most_common(top_n)
        ],
        "top_urls": [
            {"url": url, "count": count}
            for url, count in stats["url_count"].most_common(top_n)
        ],
        "status_codes": dict(stats["status_count"]),
        "hourly_distribution": dict(stats["hour_count"]),
        "attacks": dict(stats["attacks"]),
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
