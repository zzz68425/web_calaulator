"""Inspect the JSON returned by Shodan's public CT Logs API."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, TextIO
from urllib.parse import quote

import requests


BASE_URL = "https://ctl.shodan.io/api/v1/domain"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query Shodan CT Logs and print response statistics plus JSON samples."
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default="ncku.edu.tw",
        help="Root domain to query (default: ncku.edu.tw).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Number of records to print (default: 5).",
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="Print only certificates that are currently within their validity period.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Print the complete JSON response. This can be very large.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds (default: 30).",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Log path (default: logs/shodan_ct_<domain>_<timestamp>.log).",
    )
    return parser.parse_args()


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain:
        raise ValueError(f"Invalid domain: {value!r}")
    return domain.encode("idna").decode("ascii")


def certificate_state(record: dict[str, Any], now_epoch: int) -> str:
    not_before = record.get("not_before")
    not_after = record.get("not_after")
    if not isinstance(not_before, int) or not isinstance(not_after, int):
        return "unknown"
    if now_epoch < not_before:
        return "future"
    if now_epoch >= not_after:
        return "expired"
    return "active"


def collect_hostnames(records: list[dict[str, Any]]) -> set[str]:
    hostnames: set[str] = set()
    for record in records:
        subject_cn = record.get("subject_cn")
        if isinstance(subject_cn, str) and subject_cn:
            hostnames.add(subject_cn.lower().rstrip("."))

        for name in record.get("san_dns_names") or []:
            if isinstance(name, str) and name:
                hostnames.add(name.lower().rstrip("."))
    return hostnames


def query_shodan_ct(domain: str, timeout: float) -> tuple[requests.Response, float]:
    url = f"{BASE_URL}/{quote(domain, safe='.-')}"
    started = time.perf_counter()
    response = requests.get(
        url,
        timeout=(5.0, timeout),
        headers={"User-Agent": "web-calculator-shodan-ct-test/1.0"},
    )
    elapsed = time.perf_counter() - started
    return response, elapsed


class Tee:
    """Write the same output to the terminal and a log file."""

    def __init__(self, *streams: TextIO) -> None:
        self.streams = streams

    def write(self, data: str) -> int:
        for stream in self.streams:
            stream.write(data)
        return len(data)

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()


def default_log_path(domain: str) -> Path:
    safe_domain = re.sub(r"[^a-z0-9.-]+", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("logs") / f"shodan_ct_{safe_domain}_{timestamp}.log"


def run_query(args: argparse.Namespace, domain: str) -> int:
    print(f"Log file: {args.log_file.resolve()}")

    try:
        response, elapsed = query_shodan_ct(domain, args.timeout)
    except requests.RequestException as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 1

    print("=== Request ===")
    print(f"URL: {response.url}")
    print(f"HTTP status: {response.status_code}")
    print(f"Elapsed: {elapsed:.3f}s")
    print(f"Response bytes: {len(response.content):,}")
    print(f"Content-Type: {response.headers.get('Content-Type', '(missing)')}")

    try:
        response.raise_for_status()
        payload = response.json()
    except requests.HTTPError as exc:
        print(f"HTTP error: {exc}", file=sys.stderr)
        print(response.text[:2000])
        return 1
    except requests.exceptions.JSONDecodeError as exc:
        print(f"JSON decode failed: {exc}", file=sys.stderr)
        print(response.text[:2000])
        return 1

    if not isinstance(payload, list):
        print("Unexpected JSON type; expected a list of certificate objects.")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 1

    records = [item for item in payload if isinstance(item, dict)]
    now_epoch = int(time.time())
    states = [certificate_state(record, now_epoch) for record in records]
    active_records = [
        record
        for record in records
        if certificate_state(record, now_epoch) == "active"
    ]
    all_hostnames = collect_hostnames(records)
    active_hostnames = collect_hostnames(active_records)
    unique_hashes = {
        record["hash"]
        for record in records
        if isinstance(record.get("hash"), str) and record["hash"]
    }

    print("\n=== Summary ===")
    print(f"Certificate records: {len(records):,}")
    print(f"Unique certificate hashes: {len(unique_hashes):,}")
    print(f"Active records: {states.count('active'):,}")
    print(f"Expired records: {states.count('expired'):,}")
    print(f"Future records: {states.count('future'):,}")
    print(f"Unknown validity records: {states.count('unknown'):,}")
    print(f"Unique hostnames (all): {len(all_hostnames):,}")
    print(f"Unique hostnames (active records): {len(active_hostnames):,}")

    selected = active_records if args.active_only else records
    shown = selected if args.all else selected[: args.limit]
    mode = "active records" if args.active_only else "all records"
    count_label = "complete response" if args.all else f"first {len(shown)}"

    print(f"\n=== JSON: {count_label} from {mode} ===")
    print(json.dumps(shown, indent=2, ensure_ascii=False))

    if not args.all and len(selected) > len(shown):
        print(
            f"\nOutput truncated: {len(selected) - len(shown):,} more records. "
            "Use --all to print everything."
        )

    return 0


def main() -> int:
    args = parse_args()
    if args.limit < 0:
        print("error: --limit must be zero or greater", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("error: --timeout must be greater than zero", file=sys.stderr)
        return 2

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.log_file = args.log_file or default_log_path(domain)
    try:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        with args.log_file.open("w", encoding="utf-8") as log_file:
            stdout = Tee(sys.stdout, log_file)
            stderr = Tee(sys.stderr, log_file)
            with redirect_stdout(stdout), redirect_stderr(stderr):
                return run_query(args, domain)
    except OSError as exc:
        print(f"error: cannot write log file {args.log_file}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
