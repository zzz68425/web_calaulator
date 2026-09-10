"""Query SSLMate's Cert Spotter Certificate Transparency Search API."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, TextIO

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


API_URL = "https://api.certspotter.com/v1/issuances"
USER_AGENT = "web-calculator-certspotter-test/1.0"


class RateLimitReached(Exception):
    """Represent an API quota response that should be resumed later."""

    def __init__(self, response: requests.Response) -> None:
        self.response = response
        self.retry_after = response.headers.get("Retry-After")
        super().__init__(f"HTTP 429: {response.text[:500]}")


@dataclass
class FetchResult:
    records: list[dict[str, Any]]
    complete: bool
    rate_limited: bool
    resume_after: str | None
    retry_after: str | None = None
    limit_reached: bool = False


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Query unexpired certificate issuances from SSLMate Cert Spotter. "
            "Unauthenticated queries are available for evaluation."
        )
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default="evs.ncku.edu.tw",
        help="Domain to query (default: evs.ncku.edu.tw).",
    )
    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Also return certificates for subdomains at any depth.",
    )
    parser.add_argument(
        "--match-wildcards",
        action="store_true",
        help="Also return wildcard certificates that cover the queried domain.",
    )
    parser.add_argument(
        "--api-key",
        help=(
            "Cert Spotter API key. If omitted, CERTSPOTTER_API_KEY is read from "
            "the environment; otherwise an unauthenticated evaluation query is used."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP read timeout in seconds (default: 30).",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=20,
        help="Maximum number of API pages to retrieve (default: 20).",
    )
    parser.add_argument(
        "--first-50",
        action="store_true",
        help=(
            "Stop after the first 50 records and print all of them. "
            "The API still returns a 100-record page."
        ),
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Attempts for network and server errors (default: 3).",
    )
    parser.add_argument(
        "--output-limit",
        type=int,
        default=20,
        help="Maximum number of records printed to the log (default: 20).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Print every returned record. This may produce a large log.",
    )
    parser.add_argument(
        "--require-exact",
        action="store_true",
        help="Exit with status 3 when no certificate has an exact DNS-name match.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Continue an incomplete query from its saved checkpoint.",
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Discard an existing checkpoint and start the query again.",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help=(
            "Checkpoint path (default: "
            "logs/certspotter_ct_<domain>.checkpoint.json)."
        ),
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Log path (default: logs/certspotter_ct_<domain>_<timestamp>.log).",
    )
    return parser.parse_args()


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain:
        raise ValueError(f"Invalid domain: {value!r}")
    return domain.encode("idna").decode("ascii")


def default_log_path(domain: str) -> Path:
    safe_domain = re.sub(r"[^a-z0-9.-]+", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("logs") / f"certspotter_ct_{safe_domain}_{timestamp}.log"


def default_state_path(domain: str, first_50: bool) -> Path:
    safe_domain = re.sub(r"[^a-z0-9.-]+", "_", domain)
    mode_suffix = "_first50" if first_50 else ""
    return (
        Path("logs")
        / f"certspotter_ct_{safe_domain}{mode_suffix}.checkpoint.json"
    )


def normalized_dns_names(record: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in record.get("dns_names") or []:
        if not isinstance(value, str):
            continue
        name = value.strip().lower().rstrip(".")
        if name:
            result.append(name)
    return result


def has_exact_dns_name(record: dict[str, Any], domain: str) -> bool:
    return domain in normalized_dns_names(record)


def wildcard_covers_domain(wildcard: str, domain: str) -> bool:
    if not wildcard.startswith("*."):
        return False
    parent = wildcard[2:]
    return (
        domain.endswith(f".{parent}")
        and domain.count(".") == parent.count(".") + 1
    )


def has_covering_wildcard(record: dict[str, Any], domain: str) -> bool:
    return any(
        wildcard_covers_domain(name, domain)
        for name in normalized_dns_names(record)
    )


def save_checkpoint(
    path: Path,
    domain: str,
    args: argparse.Namespace,
    records: list[dict[str, Any]],
    after: str | None,
    complete: bool,
) -> None:
    payload = {
        "version": 1,
        "domain": domain,
        "include_subdomains": args.include_subdomains,
        "match_wildcards": args.match_wildcards,
        "first_50": args.first_50,
        "after": after,
        "complete": complete,
        "updated_at": datetime.now().astimezone().isoformat(),
        "records": records,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f"{path.name}.tmp")
    with temporary_path.open("w", encoding="utf-8") as checkpoint_file:
        json.dump(payload, checkpoint_file, indent=2, ensure_ascii=False)
        checkpoint_file.write("\n")
    temporary_path.replace(path)


def load_checkpoint(
    path: Path,
    domain: str,
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], str | None, bool]:
    try:
        with path.open("r", encoding="utf-8") as checkpoint_file:
            payload = json.load(checkpoint_file)
    except FileNotFoundError as exc:
        raise ValueError(f"Checkpoint does not exist: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read checkpoint {path}: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError(f"Unsupported checkpoint format: {path}")

    expected = {
        "domain": domain,
        "include_subdomains": args.include_subdomains,
        "match_wildcards": args.match_wildcards,
        "first_50": args.first_50,
    }
    mismatches = [
        key for key, value in expected.items() if payload.get(key) != value
    ]
    if mismatches:
        raise ValueError(
            "Checkpoint query options do not match: " + ", ".join(mismatches)
        )

    raw_records = payload.get("records")
    if not isinstance(raw_records, list):
        raise ValueError(f"Checkpoint records are invalid: {path}")
    records = [item for item in raw_records if isinstance(item, dict)]

    after = payload.get("after")
    if after is not None and not isinstance(after, str):
        raise ValueError(f"Checkpoint after cursor is invalid: {path}")

    return records, after, payload.get("complete") is True


def retry_delay(response: requests.Response | None, attempt: int) -> float:
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(60.0, max(0.0, float(retry_after)))
            except ValueError:
                pass
    return min(8.0, 2.0 ** (attempt - 1))


def get_page(
    session: requests.Session,
    params: list[tuple[str, str]],
    timeout: float,
    retries: int,
) -> tuple[list[dict[str, Any]], requests.Response, float]:
    last_error: requests.RequestException | None = None

    for attempt in range(1, retries + 1):
        response: requests.Response | None = None
        started = time.perf_counter()
        try:
            response = session.get(
                API_URL,
                params=params,
                timeout=(5.0, timeout),
            )
            elapsed = time.perf_counter() - started

            if response.status_code == 429:
                raise RateLimitReached(response)
            if response.status_code >= 500:
                response.raise_for_status()

            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                raise ValueError(
                    f"Unexpected JSON type: {type(payload).__name__}; expected list"
                )

            records = [item for item in payload if isinstance(item, dict)]
            return records, response, elapsed
        except (RateLimitReached, ValueError):
            raise
        except requests.RequestException as exc:
            last_error = exc
            elapsed = time.perf_counter() - started
            if attempt >= retries:
                raise

            delay = retry_delay(response, attempt)
            status = response.status_code if response is not None else "network"
            print(
                f"Request attempt {attempt}/{retries} failed "
                f"(status={status}, elapsed={elapsed:.3f}s): {exc}"
            )
            print(f"Retrying in {delay:.1f}s...")
            time.sleep(delay)

    assert last_error is not None
    raise last_error


def fetch_issuances(
    session: requests.Session,
    domain: str,
    args: argparse.Namespace,
    initial_records: list[dict[str, Any]],
    initial_after: str | None,
) -> FetchResult:
    base_params = [
        ("domain", domain),
        ("include_subdomains", str(args.include_subdomains).lower()),
        ("match_wildcards", str(args.match_wildcards).lower()),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    records = list(initial_records)
    seen_ids = {
        record["id"]
        for record in records
        if isinstance(record.get("id"), str) and record["id"]
    }
    after = initial_after

    for page_number in range(1, args.max_pages + 1):
        params = list(base_params)
        if after is not None:
            params.append(("after", after))

        try:
            page, response, elapsed = get_page(
                session,
                params,
                args.timeout,
                args.retries,
            )
        except RateLimitReached as exc:
            save_checkpoint(
                args.state_file,
                domain,
                args,
                records,
                after,
                complete=False,
            )
            return FetchResult(
                records=records,
                complete=False,
                rate_limited=True,
                resume_after=after,
                retry_after=exc.retry_after,
            )

        print(
            f"Page {page_number}: HTTP {response.status_code}, "
            f"{len(page)} records, {elapsed:.3f}s"
        )

        if not page:
            save_checkpoint(
                args.state_file,
                domain,
                args,
                records,
                after,
                complete=True,
            )
            return FetchResult(
                records=records,
                complete=True,
                rate_limited=False,
                resume_after=after,
            )

        for record in page:
            record_id = record.get("id")
            if isinstance(record_id, str) and record_id:
                if record_id in seen_ids:
                    continue
                seen_ids.add(record_id)
            records.append(record)

        if args.first_50 and len(records) >= 50:
            return FetchResult(
                records=records[:50],
                complete=False,
                rate_limited=False,
                resume_after=None,
                limit_reached=True,
            )

        last_id = page[-1].get("id")
        if not isinstance(last_id, str) or not last_id:
            print("Pagination stopped: the final record has no usable id.")
            save_checkpoint(
                args.state_file,
                domain,
                args,
                records,
                after,
                complete=False,
            )
            return FetchResult(records, False, False, after)
        if last_id == after:
            print("Pagination stopped: the API returned the same final id.")
            save_checkpoint(
                args.state_file,
                domain,
                args,
                records,
                after,
                complete=False,
            )
            return FetchResult(records, False, False, after)
        after = last_id
        save_checkpoint(
            args.state_file,
            domain,
            args,
            records,
            after,
            complete=False,
        )

    print(f"Pagination paused after reaching --max-pages={args.max_pages}.")
    return FetchResult(records, False, False, after)


def resume_command(args: argparse.Namespace, domain: str) -> str:
    parts = [
        "uv run python tests/manual/certspotter_ct_test.py",
        domain,
    ]
    if args.include_subdomains:
        parts.append("--include-subdomains")
    if args.match_wildcards:
        parts.append("--match-wildcards")
    if args.first_50:
        parts.append("--first-50")
    if args.all:
        parts.append("--all")
    else:
        parts.extend(["--output-limit", str(args.output_limit)])
    parts.append("--resume")
    return " ".join(parts)


def run_query(args: argparse.Namespace, domain: str, api_key: str | None) -> int:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
    )
    if api_key:
        session.headers["Authorization"] = f"Bearer {api_key}"

    print("=== Cert Spotter CT Search API Test ===")
    print(f"Domain: {domain}")
    print(f"Authentication: {'API key' if api_key else 'unauthenticated evaluation'}")
    print(f"Include subdomains: {args.include_subdomains}")
    print(f"Match wildcard certificates: {args.match_wildcards}")
    print(f"First 50 records only: {args.first_50}")
    print("Data scope: unexpired certificate issuances only")
    print(f"Log file: {args.log_file.resolve()}")
    print(f"Checkpoint file: {args.state_file.resolve()}")
    print()

    initial_records: list[dict[str, Any]] = []
    initial_after: str | None = None
    checkpoint_complete = False
    if args.resume:
        try:
            initial_records, initial_after, checkpoint_complete = load_checkpoint(
                args.state_file,
                domain,
                args,
            )
        except ValueError as exc:
            print(f"Cannot resume: {exc}", file=sys.stderr)
            return 2
        print(
            f"Resuming checkpoint: {len(initial_records)} records, "
            f"after={initial_after or '(none)'}"
        )
    elif args.state_file.exists() and not args.restart:
        print(
            f"An incomplete checkpoint already exists: {args.state_file.resolve()}",
            file=sys.stderr,
        )
        print(
            "Use --resume to continue it or --restart to discard it.",
            file=sys.stderr,
        )
        return 2
    else:
        try:
            save_checkpoint(
                args.state_file,
                domain,
                args,
                initial_records,
                initial_after,
                complete=False,
            )
        except OSError as exc:
            print(f"Cannot create checkpoint: {exc}", file=sys.stderr)
            return 1

    try:
        if checkpoint_complete:
            result = FetchResult(
                records=initial_records,
                complete=True,
                rate_limited=False,
                resume_after=initial_after,
            )
        else:
            result = fetch_issuances(
                session,
                domain,
                args,
                initial_records,
                initial_after,
            )
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        print(
            f"Saved progress can be resumed with:\n{resume_command(args, domain)}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"Cannot save checkpoint: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Invalid API response: {exc}", file=sys.stderr)
        return 1
    finally:
        session.close()

    records = result.records
    exact_records = [
        record for record in records if has_exact_dns_name(record, domain)
    ]
    wildcard_records = [
        record for record in records if has_covering_wildcard(record, domain)
    ]
    unique_tbs_hashes = {
        record["tbs_sha256"]
        for record in records
        if isinstance(record.get("tbs_sha256"), str) and record["tbs_sha256"]
    }

    print("\n=== Summary ===")
    print(f"Pagination complete: {result.complete}")
    print(f"Rate limited: {result.rate_limited}")
    print(f"First-50 limit reached: {result.limit_reached}")
    print(f"Returned records: {len(records)}")
    print(f"Unique issuance hashes: {len(unique_tbs_hashes)}")
    print(f"Exact DNS-name matches: {len(exact_records)}")
    print(f"Covering wildcard records: {len(wildcard_records)}")
    if result.resume_after:
        print(f"Resume after: {result.resume_after}")
    if result.retry_after:
        print(f"Server Retry-After: {result.retry_after}")

    selected = records if args.all or args.first_50 else records[: args.output_limit]
    print(f"\n=== JSON Records ({len(selected)}/{len(records)}) ===")
    print(json.dumps(selected, indent=2, ensure_ascii=False))
    if len(selected) < len(records):
        print(
            f"\nOutput truncated: {len(records) - len(selected)} more records. "
            "Use --all to print every record."
        )

    if result.limit_reached:
        print("\nStopped intentionally after the first 50 records.")
    elif not result.complete:
        print("\nThe query is incomplete; progress was saved.")
        print("Resume later with:")
        print(resume_command(args, domain))
        return 4

    if result.complete or result.limit_reached:
        try:
            args.state_file.unlink(missing_ok=True)
        except OSError as exc:
            print(f"\nWarning: cannot remove completed checkpoint: {exc}")

    if args.require_exact and not exact_records:
        print(
            f"\nNo exact DNS-name match was found for {domain}.",
            file=sys.stderr,
        )
        return 3
    return 0


def main() -> int:
    args = parse_args()
    if args.resume and args.restart:
        print("error: --resume and --restart cannot be used together", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("error: --timeout must be greater than zero", file=sys.stderr)
        return 2
    if args.max_pages <= 0:
        print("error: --max-pages must be greater than zero", file=sys.stderr)
        return 2
    if args.retries <= 0:
        print("error: --retries must be greater than zero", file=sys.stderr)
        return 2
    if args.output_limit < 0:
        print("error: --output-limit must be zero or greater", file=sys.stderr)
        return 2

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if load_dotenv is not None:
        load_dotenv()
    api_key = args.api_key or os.getenv("CERTSPOTTER_API_KEY")

    args.log_file = args.log_file or default_log_path(domain)
    args.state_file = args.state_file or default_state_path(domain, args.first_50)
    try:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        with args.log_file.open("w", encoding="utf-8") as log_file:
            stdout = Tee(sys.stdout, log_file)
            stderr = Tee(sys.stderr, log_file)
            with redirect_stdout(stdout), redirect_stderr(stderr):
                return run_query(args, domain, api_key)
    except OSError as exc:
        print(f"error: cannot write log file {args.log_file}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
