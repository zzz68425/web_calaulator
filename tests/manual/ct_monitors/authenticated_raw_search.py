"""Fetch raw MerkleMap and Censys CT search responses without logging tokens."""

from __future__ import annotations

import argparse
from datetime import datetime
from getpass import getpass
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "logs" / "ct_monitors" / "raw"
USER_AGENT = "web-calculator-ct-raw-test/1.0"
TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Save raw MerkleMap and Censys CT search JSON responses."
    )
    parser.add_argument("domain", nargs="?", default="ncku.edu.tw")
    parser.add_argument(
        "--provider",
        choices=("both", "merklemap", "censys"),
        default="both",
    )
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--censys-organization-id",
        default=os.getenv("CENSYS_ORGANIZATION_ID"),
        help="Paid Censys organization ID (or set CENSYS_ORGANIZATION_ID).",
    )
    return parser.parse_args()


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain or ":" in domain:
        raise ValueError(f"Invalid domain: {value!r}")
    return domain.encode("idna").decode("ascii")


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "_", value.lower())


def read_token(env_name: str, prompt: str) -> str:
    value = os.getenv(env_name)
    if value:
        print(f"Using {env_name} from the process environment.")
        return value
    value = getpass(prompt).strip()
    if not value:
        raise ValueError(f"{env_name} is required")
    return value


def request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: float,
    retries: int,
    **kwargs: Any,
) -> requests.Response:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        started = time.perf_counter()
        try:
            response = session.request(method, url, timeout=timeout, **kwargs)
            elapsed = time.perf_counter() - started
            print(
                f"  attempt {attempt}/{retries}: HTTP {response.status_code}, "
                f"{elapsed:.3f}s"
            )
            if response.status_code not in TRANSIENT_STATUS_CODES:
                return response
            last_error = requests.HTTPError(
                f"HTTP {response.status_code}: {response.text[:500]}",
                response=response,
            )
            if attempt == retries:
                return response
            retry_after = response.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else 2 ** (attempt - 1)
            except ValueError:
                delay = 2 ** (attempt - 1)
            delay = min(max(delay, 0.25), 30.0)
            print(f"  retrying in {delay:.1f}s")
            time.sleep(delay)
        except requests.RequestException as exc:
            last_error = exc
            print(f"  attempt {attempt}/{retries} failed: {exc}")
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 8))
    assert last_error is not None
    raise last_error


def response_payload(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {
            "http_status": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "text": response.text,
        }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def print_shape(payload: Any) -> None:
    if isinstance(payload, dict):
        print(f"  top-level keys: {', '.join(payload)}")
    elif isinstance(payload, list):
        print(f"  top-level type: array ({len(payload)} items)")
    else:
        print(f"  top-level type: {type(payload).__name__}")


def query_merklemap(
    token: str,
    domain: str,
    limit: int,
    timeout: float,
    retries: int,
    output_dir: Path,
    timestamp: str,
) -> dict[str, Any]:
    endpoint = "https://api.merklemap.com/v1/search"
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
        }
    )
    query = f"*.{domain}"
    combined: list[Any] = []
    raw_files: list[str] = []
    page = 0
    total: int | None = None
    final_status: int | None = None

    print(f"MerkleMap query: {query}")
    while len(combined) < limit and page < 50:
        response = request_with_retry(
            session,
            "GET",
            endpoint,
            timeout=timeout,
            retries=retries,
            params={"query": query, "type": "wildcard", "page": page},
        )
        final_status = response.status_code
        payload = response_payload(response)
        raw_path = output_dir / (
            f"merklemap_raw_{safe_name(domain)}_{timestamp}_page_{page}.json"
        )
        write_json(raw_path, payload)
        raw_files.append(str(raw_path.resolve()))
        print(f"  raw page saved: {raw_path.resolve()}")
        print_shape(payload)

        if not response.ok or not isinstance(payload, dict):
            break
        results = payload.get("results")
        if not isinstance(results, list):
            break
        if isinstance(payload.get("count"), int):
            total = payload["count"]
        combined.extend(results)
        print(f"  page {page}: {len(results)} results; collected {len(combined)}")
        if not results or (total is not None and len(combined) >= total):
            break
        page += 1

    first_results = combined[:limit]
    aggregate = {
        "provider": "MerkleMap",
        "request": {
            "endpoint": endpoint,
            "query": query,
            "type": "wildcard",
            "first_page": 0,
        },
        "http_status": final_status,
        "reported_total": total,
        "collected_before_limit": len(combined),
        "returned_first_n": len(first_results),
        "raw_page_files": raw_files,
        "results": first_results,
    }
    aggregate_path = output_dir / (
        f"merklemap_first_{limit}_{safe_name(domain)}_{timestamp}.json"
    )
    write_json(aggregate_path, aggregate)
    aggregate["aggregate_file"] = str(aggregate_path.resolve())
    print(f"  first-{limit} file: {aggregate_path.resolve()}")
    if first_results and isinstance(first_results[0], dict):
        print(f"  first result keys: {', '.join(first_results[0])}")
    return aggregate


def censys_subdomain_query(domain: str) -> str:
    escaped = re.escape(domain)
    return f"cert.names=~`^.*\\.{escaped}$`"


def censys_hits(payload: Any) -> list[Any]:
    if not isinstance(payload, dict):
        return []
    candidates = [
        payload.get("hits"),
        payload.get("results"),
    ]
    result = payload.get("result")
    if isinstance(result, dict):
        candidates.extend([result.get("hits"), result.get("results")])
    for candidate in candidates:
        if isinstance(candidate, list):
            return candidate
    return []


def query_censys(
    token: str,
    organization_id: str | None,
    domain: str,
    limit: int,
    timeout: float,
    retries: int,
    output_dir: Path,
    timestamp: str,
) -> dict[str, Any]:
    endpoint = "https://api.platform.censys.io/v3/global/search/query"
    query = censys_subdomain_query(domain)
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
    )
    print(f"Censys query: {query}")
    response = request_with_retry(
        session,
        "POST",
        endpoint,
        timeout=timeout,
        retries=retries,
        params={"organization_id": organization_id} if organization_id else None,
        json={"query": query, "page_size": min(limit, 100)},
    )
    payload = response_payload(response)
    raw_path = output_dir / f"censys_raw_{safe_name(domain)}_{timestamp}.json"
    write_json(raw_path, payload)
    hits = censys_hits(payload)
    print(f"  raw response saved: {raw_path.resolve()}")
    print_shape(payload)
    print(f"  extracted hits: {len(hits)}")
    if hits and isinstance(hits[0], dict):
        print(f"  first hit keys: {', '.join(hits[0])}")
    return {
        "provider": "Censys",
        "request": {
            "endpoint": endpoint,
            "query": query,
            "page_size": min(limit, 100),
            "organization_id_supplied": bool(organization_id),
        },
        "http_status": response.status_code,
        "returned_hits": len(hits),
        "raw_file": str(raw_path.resolve()),
        "first_hit": hits[0] if hits else None,
    }


def main() -> int:
    args = parse_args()
    try:
        domain = normalize_domain(args.domain)
        if args.limit < 1 or args.limit > 100:
            raise ValueError("--limit must be between 1 and 100")
        if args.retries < 1:
            raise ValueError("--retries must be at least 1")
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 1

    output_dir = args.output_dir.resolve()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summaries: list[dict[str, Any]] = []
    exit_code = 0

    if args.provider in {"both", "merklemap"}:
        try:
            token = read_token("MERKLEMAP_API_TOKEN", "MerkleMap API token: ")
            summaries.append(
                query_merklemap(
                    token,
                    domain,
                    args.limit,
                    args.timeout,
                    args.retries,
                    output_dir,
                    timestamp,
                )
            )
        except Exception as exc:
            exit_code = 1
            summaries.append({"provider": "MerkleMap", "error": f"{type(exc).__name__}: {exc}"})
            print(f"MerkleMap error: {type(exc).__name__}: {exc}", file=sys.stderr)

    if args.provider in {"both", "censys"}:
        try:
            token = read_token("CENSYS_API_TOKEN", "Censys API token: ")
            summaries.append(
                query_censys(
                    token,
                    args.censys_organization_id,
                    domain,
                    args.limit,
                    args.timeout,
                    args.retries,
                    output_dir,
                    timestamp,
                )
            )
        except Exception as exc:
            exit_code = 1
            summaries.append({"provider": "Censys", "error": f"{type(exc).__name__}: {exc}"})
            print(f"Censys error: {type(exc).__name__}: {exc}", file=sys.stderr)

    summary_path = output_dir / f"authenticated_raw_summary_{safe_name(domain)}_{timestamp}.json"
    write_json(summary_path, {"domain": domain, "limit": args.limit, "providers": summaries})
    print(f"Summary saved: {summary_path.resolve()}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
