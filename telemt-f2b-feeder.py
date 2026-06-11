#!/usr/bin/env python3
"""
telemt-f2b-feeder.py — читает плохие IP из Telemt TLS Fingerprints API
и пишет их в лог-файл для Fail2ban.

Запускается из cron или systemd.timer каждые 2-5 минут.
Fail2ban читает этот лог и банит IP на заданное время.

Использование:
    python3 telemt-f2b-feeder.py

Конфиг через переменные окружения (или .env файл):
    TELEMT_URL=http://127.0.0.1:9091
    TELEMT_AUTH=Bearer <token>       # если нужна авторизация
    F2B_LOG=/var/log/telemt-bad-fp.log
    FP_LIMIT=1000                    # limit для /v1/runtime/tls-fingerprints
    API_RETRIES=3                    # количество повторных попыток
    API_RETRY_DELAY=2                # задержка между попытками (сек)
    LOG_MAX_SIZE=10485760            # максимальный размер лога (10MB)
    LOG_BACKUP_COUNT=5               # количество бэкапов лога
"""

import json
import logging
import os
import signal
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ── Конфиг ────────────────────────────────────────────────────────────────────

TELEMT_URL  = os.environ.get("TELEMT_URL", "http://127.0.0.1:9091")
TELEMT_AUTH = os.environ.get("TELEMT_AUTH", "")
F2B_LOG     = os.environ.get("F2B_LOG", "/var/log/telemt-bad-fp.log")
FP_LIMIT    = int(os.environ.get("FP_LIMIT", "1000"))

# Минимальное соотношение плохих к общим чтобы IP попал в бан
# 1.0 = только если ВСЕ соединения с этого IP плохие
# 0.5 = банить если более 50% соединений плохие
BAD_RATIO_THRESHOLD = float(os.environ.get("BAD_RATIO_THRESHOLD", "1.0"))

# Минимальное число плохих соединений для бана (защита от единичных зондов)
MIN_BAD_COUNT = int(os.environ.get("MIN_BAD_COUNT", "1"))

# Retry settings
API_RETRIES    = int(os.environ.get("API_RETRIES", "3"))
API_RETRY_DELAY = int(os.environ.get("API_RETRY_DELAY", "2"))

# Log rotation settings
LOG_MAX_SIZE    = int(os.environ.get("LOG_MAX_SIZE", "10485760"))  # 10MB
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("telemt-f2b")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler (for systemd journal)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler with rotation
    log_path = Path(F2B_LOG)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        F2B_LOG,
        maxBytes=LOG_MAX_SIZE,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


log = setup_logging()


# ── Graceful shutdown ─────────────────────────────────────────────────────────

_shutdown = False

def handle_signal(signum, frame):
    global _shutdown
    _shutdown = True
    log.info("Received signal %d, shutting down...", signum)

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


# ── Fetch API ─────────────────────────────────────────────────────────────────

def fetch_fingerprints() -> dict:
    url = f"{TELEMT_URL}/v1/runtime/tls-fingerprints?limit={FP_LIMIT}"

    last_error = None
    for attempt in range(1, API_RETRIES + 1):
        if _shutdown:
            log.info("Shutdown requested, aborting fetch")
            sys.exit(0)

        req = urllib.request.Request(url)
        if TELEMT_AUTH:
            req.add_header("Authorization", TELEMT_AUTH)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                return json.loads(raw)
        except json.JSONDecodeError as e:
            last_error = f"Invalid JSON response: {e}"
            log.warning("Attempt %d/%d failed: %s", attempt, API_RETRIES, last_error)
        except urllib.error.URLError as e:
            last_error = str(e)
            log.warning("Attempt %d/%d failed: %s", attempt, API_RETRIES, last_error)
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}: {e.reason}"
            log.warning("Attempt %d/%d failed: %s", attempt, API_RETRIES, last_error)

        if attempt < API_RETRIES:
            time.sleep(API_RETRY_DELAY)

    log.error("All %d attempts failed, last error: %s", API_RETRIES, last_error)
    raise ConnectionError(f"Cannot reach Telemt API after {API_RETRIES} attempts: {last_error}")


# ── Логика определения плохих IP ──────────────────────────────────────────────

def get_bad_ips(data: dict) -> list[str]:
    """
    Возвращает список IP у которых все соединения плохие (bad_or_probe).
    Использует by_ip — агрегация по конкретному IP адресу.
    """
    inner = data.get("data", {})
    by_ip = inner.get("by_ip", [])

    # Группируем по scope (IP), суммируем по всем fingerprints с этого IP
    ip_stats: dict[str, dict] = {}
    for entry in by_ip:
        ip = entry.get("scope", "")
        if not ip:
            continue
        if ip not in ip_stats:
            ip_stats[ip] = {"total": 0, "bad": 0}
        ip_stats[ip]["total"] += entry.get("total", 0)
        ip_stats[ip]["bad"]   += entry.get("bad_or_probe", 0)

    bad_ips = []
    for ip, stats in ip_stats.items():
        bad   = stats["bad"]
        total = stats["total"]
        if bad < MIN_BAD_COUNT:
            continue
        ratio = bad / total if total > 0 else 0
        if ratio >= BAD_RATIO_THRESHOLD:
            bad_ips.append(ip)

    return bad_ips


# ── Запись в лог для Fail2ban ─────────────────────────────────────────────────

def write_log(ips: list[str]) -> int:
    """
    Пишет строки в лог-файл.
    Формат: <timestamp> telemt-bad-fp: BAD_FP ip=<IP>
    Fail2ban фильтр ищет именно эту строку.
    Возвращает количество записанных IP.
    """
    if not ips:
        return 0

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    written = 0
    for ip in ips:
        log.info("BAD_FP ip=%s", ip)
        written += 1

    return written


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("Starting telemt-f2b-feeder")

    try:
        result = fetch_fingerprints()
    except ConnectionError as e:
        log.error("Cannot reach Telemt API: %s", e)
        sys.exit(1)

    if not result.get("ok"):
        log.error("API returned not ok: %s", result)
        sys.exit(1)

    data    = result.get("data", {})
    enabled = data.get("enabled", False)

    if not enabled:
        reason = data.get("reason", "unknown")
        log.warning("TLS fingerprints not enabled: %s", reason)
        sys.exit(0)

    bad_ips = get_bad_ips(data)
    written = write_log(bad_ips)

    if written:
        log.info("Wrote %d bad IP(s) to %s: %s", written, F2B_LOG, ", ".join(bad_ips))
    else:
        log.info("No bad IPs found.")


if __name__ == "__main__":
    main()
