"""HTML report export support."""

from datetime import datetime


def generate_html_report(stats: dict, log_file: str, output_file: str) -> None:
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dobivorn Log Analyzer v3.0 Report</title>
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
        .attack {{ background: #ffe6e6; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Dobivorn Log Analyzer v3.0 Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Log File: {log_file}</p>

        <div class="stats">
            <div class="card"><h3>Total Requests</h3><p>{stats['total_requests']}</p></div>
            <div class="card"><h3>Unique IPs</h3><p>{len(stats['unique_ips'])}</p></div>
            <div class="card"><h3>Bot Requests</h3><p>{stats['bot_count']}</p></div>
            <div class="card"><h3>Attacks Detected</h3><p>{sum(stats['attacks'].values())}</p></div>
        </div>

        <h2>Top IPs</h2>
        <table>
            <tr><th>IP Address</th><th>Requests</th></tr>
            {''.join(f'<tr><td>{ip}</td><td>{count}</td></tr>' for ip, count in stats['ip_count'].most_common(10))}
        </table>

        <h2>Top URLs</h2>
        <table>
            <tr><th>URL</th><th>Requests</th></tr>
            {''.join(f'<tr><td>{url[:80]}</td><td>{count}</td></tr>' for url, count in stats['url_count'].most_common(10))}
        </table>

        <h2>Status Codes</h2>
        <table>
            <tr><th>Status</th><th>Count</th></tr>
            {''.join(f'<tr><td>{status}</td><td>{count}</td></tr>' for status, count in sorted(stats['status_count'].items()))}
        </table>

        <h2>Attacks Detected</h2>
        <table>
            <tr><th>Attack Type</th><th>Count</th></tr>
            {''.join(f'<tr class="attack"><td>{attack}</td><td>{count}</td></tr>' for attack, count in stats['attacks'].most_common()) if stats['attacks'] else '<tr><td colspan="2">No attacks detected</td></tr>'}
        </table>
    </div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
