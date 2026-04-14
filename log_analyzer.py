#!/usr/bin/env python3
"""Dobivorn Log Analyzer v3.0 CLI entrypoint."""

import argparse

from core import DobivornLogAnalyzer
from core.constants import BANNER, VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Dobivorn Log Analyzer v{VERSION} - Web Server Log Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py access.log
  python log_analyzer.py access.log -n 20
  python log_analyzer.py access.log --realtime
  python log_analyzer.py access.log --geoip -j report.json
  python log_analyzer.py access.log --html report.html
        """,
    )

    parser.add_argument("log_file", help="Log file path")
    parser.add_argument("-n", "--top", type=int, default=10, help="Top N entries to show (default: 10)")
    parser.add_argument("-j", "--json", help="JSON output file")
    parser.add_argument("-c", "--csv", help="CSV output file")
    parser.add_argument("--html", help="HTML report output file")
    parser.add_argument("--realtime", action="store_true", help="Realtime log monitoring mode")
    parser.add_argument("--geoip", action="store_true", help="Enable GeoIP lookup")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    print(BANNER)

    analyzer = DobivornLogAnalyzer(
        log_file=args.log_file,
        top_n=args.top,
        realtime=args.realtime,
        geoip=args.geoip,
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
            analyzer.export_html(args.html)


if __name__ == "__main__":
    main()
