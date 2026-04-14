"""Constants for Dobivorn Log Analyzer v3.0."""

from colorama import Fore, Style

VERSION = "3.0"

BANNER = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════════╗
║   Dobivorn Log Analyzer v{VERSION} - 3 Headed Dragon         ║
║   Red Team | Purple Team | Blue Team                         ║
║   Real-time | GeoIP | HTML Report | Anomaly Detection        ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

BOT_PATTERNS = [
    "bot",
    "spider",
    "crawler",
    "scanner",
    "nmap",
    "curl",
    "wget",
    "python",
    "go-http-client",
]

ATTACK_PATTERNS = [
    ("wp-admin", "WordPress brute-force"),
    ("xmlrpc.php", "XML-RPC attack"),
    (".env", "Environment file access"),
    ("backup.zip", "Backup file access"),
    ("phpmyadmin", "phpMyAdmin access"),
    ("sqlmap", "SQLMap detected"),
    ("/../", "Path traversal"),
    ("union select", "SQL injection"),
]
