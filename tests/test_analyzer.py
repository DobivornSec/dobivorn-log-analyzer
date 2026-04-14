from core.analyzer import DobivornLogAnalyzer
from core.parser import parse_log_line


def test_parse_log_line_success():
    line = '192.168.1.1 - - [14/Apr/2026:10:15:23 +0300] "GET /index.html HTTP/1.1" 200 2326'
    parsed = parse_log_line(line)

    assert parsed is not None
    assert parsed["ip"] == "192.168.1.1"
    assert parsed["method"] == "GET"
    assert parsed["url"] == "/index.html"
    assert parsed["status"] == 200


def test_process_line_updates_stats():
    analyzer = DobivornLogAnalyzer(log_file="sample.log")
    line = '192.168.1.6 - - [14/Apr/2026:10:16:26 +0300] "GET /backup.zip HTTP/1.1" 404 0'

    parsed = analyzer.process_line(line)

    assert parsed is not None
    assert analyzer.stats["total_requests"] == 1
    assert analyzer.stats["status_count"][404] == 1
    assert analyzer.stats["attacks"]["Backup file access"] == 1
