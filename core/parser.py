"""Log parser helpers."""

import re
from datetime import datetime
from typing import Optional

LOG_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
)


def parse_log_line(line: str) -> Optional[dict]:
    """Parse a log line in Apache/Nginx common patterns."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    ip = match.group(1)
    time_str = match.group(2)
    method = match.group(3)
    url = match.group(4)
    status = int(match.group(6))

    try:
        time_obj = datetime.strptime(time_str[:20], "%d/%b/%Y:%H:%M:%S")
        hour = time_obj.hour
        date = time_obj.strftime("%Y-%m-%d")
    except ValueError:
        hour = 0
        date = "Unknown"

    return {
        "ip": ip,
        "hour": hour,
        "date": date,
        "method": method,
        "url": url,
        "status": status,
    }
