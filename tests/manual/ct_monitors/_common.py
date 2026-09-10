"""Shared runner for the standalone Certificate Transparency monitor tests."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html import unescape
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Iterable
from urllib.parse import quote, urlparse

import requests

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - uv installs this project dependency.
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOG_DIR = PROJECT_ROOT / "logs" / "ct_monitors"
DEFAULT_DOMAIN = "evs.ncku.edu.tw"
USER_AGENT = "web-calculator-ct-monitor-test/1.0"
TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class ProviderSpec:
    slug: str
    name: str
    mode: str
    auth: str
    docs_url: str
    limitation: str
    required_env: tuple[str, ...] = ()


@dataclass
class ProviderResult:
    provider: str
    provider_slug: str
    domain: str
    status: str
    query_supported: bool
    mode: str
    authentication: str
    endpoint: str | None = None
    http_status: int | None = None
    elapsed_seconds: float = 0.0
    source_total: int | None = None
    returned_records: int = 0
    exact_matches: int = 0
    in_scope_matches: int = 0
    records: list[dict[str, Any]] = field(default_factory=list)
    required_env: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None
    log_file: str | None = None

    def summary_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("records", None)
        return value


class Reporter:
    """Write complete output to a log while keeping console output concise."""

    def __init__(self, log_path: Path, console: bool = True) -> None:
        self.log_path = log_path
        self.console = console
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = log_path.open("w", encoding="utf-8", newline="\n")

    def close(self) -> None:
        self._stream.close()

    def line(self, value: str = "", *, console: bool = True) -> None:
        self._stream.write(value + "\n")
        self._stream.flush()
        if self.console and console:
            print(value, flush=True)

    def json(self, value: Any, *, console: bool = False) -> None:
        self.line(
            json.dumps(value, ensure_ascii=False, sort_keys=True, default=str),
            console=console,
        )


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain or ":" in domain:
        raise ValueError(f"Invalid domain: {value!r}")
    return domain.encode("idna").decode("ascii")


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "_", value.lower())


def default_log_path(provider_slug: str, domain: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return LOG_DIR / f"{provider_slug}_{safe_name(domain)}_{timestamp}.log"


def normalize_dns_name(value: str) -> str:
    return value.strip().lower().rstrip(".")


def unique_strings(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        normalized = normalize_dns_name(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def name_is_in_scope(name: str, domain: str, include_subdomains: bool) -> bool:
    normalized = normalize_dns_name(name)
    if normalized == domain:
        return True
    if normalized == f"*.{domain}":
        return include_subdomains
    normalized = normalized.removeprefix("*.")
    return include_subdomains and normalized.endswith(f".{domain}")


def record_dns_names(record: dict[str, Any]) -> list[str]:
    values = record.get("dns_names") or []
    if isinstance(values, str):
        values = [values]
    return unique_strings(values)


def classify_records(
    result: ProviderResult,
    records: list[dict[str, Any]],
    domain: str,
    include_subdomains: bool,
    limit: int,
) -> ProviderResult:
    exact = 0
    in_scope = 0
    for record in records:
        names = record_dns_names(record)
        if domain in names:
            exact += 1
        if any(name_is_in_scope(name, domain, include_subdomains) for name in names):
            in_scope += 1

    result.returned_records = len(records)
    result.exact_matches = exact
    result.in_scope_matches = in_scope
    result.records = records[:limit]
    if exact:
        result.status = "found_exact"
    elif in_scope:
        result.status = "found_in_scope"
    else:
        result.status = "not_found"
    return result


def load_environment() -> None:
    if load_dotenv is not None:
        load_dotenv(PROJECT_ROOT / ".env", override=False)


def missing_environment(names: Iterable[str]) -> list[str]:
    return [name for name in names if not os.getenv(name)]


def credential_result(spec: ProviderSpec, domain: str) -> ProviderResult:
    missing = missing_environment(spec.required_env)
    return ProviderResult(
        provider=spec.name,
        provider_slug=spec.slug,
        domain=domain,
        status="credentials_required",
        query_supported=True,
        mode=spec.mode,
        authentication=spec.auth,
        required_env=missing or list(spec.required_env),
        notes=[spec.limitation],
    )


def unsupported_result(spec: ProviderSpec, domain: str) -> ProviderResult:
    return ProviderResult(
        provider=spec.name,
        provider_slug=spec.slug,
        domain=domain,
        status="no_equivalent_domain_search",
        query_supported=False,
        mode=spec.mode,
        authentication=spec.auth,
        required_env=list(spec.required_env),
        notes=[spec.limitation, f"Official reference: {spec.docs_url}"],
    )


def create_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
            "User-Agent": USER_AGENT,
        }
    )
    return session


def request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    reporter: Reporter,
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
            reporter.line(
                f"HTTP attempt {attempt}/{retries}: {response.status_code} "
                f"in {elapsed:.3f}s",
                console=False,
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
            delay = min(max(delay, 0.25), 15.0)
            reporter.line(f"Transient response; retrying in {delay:.1f}s.")
            time.sleep(delay)
        except requests.RequestException as exc:
            elapsed = time.perf_counter() - started
            last_error = exc
            reporter.line(
                f"HTTP attempt {attempt}/{retries} failed in {elapsed:.3f}s: {exc}"
            )
            if attempt < retries:
                delay = min(2 ** (attempt - 1), 8)
                reporter.line(f"Retrying in {delay:.1f}s.")
                time.sleep(delay)
    assert last_error is not None
    raise last_error


def require_success(response: requests.Response) -> None:
    if response.ok:
        return
    body = response.text[:1000].replace("\n", " ")
    raise requests.HTTPError(
        f"HTTP {response.status_code} from {response.url}: {body}",
        response=response,
    )


TAG_RE = re.compile(r"<[^>]+>")


def text_from_html(value: str) -> str:
    return " ".join(unescape(TAG_RE.sub(" ", value)).split())


def deduplicate_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key_parts = (
            str(record.get("id") or ""),
            str(record.get("serial") or ""),
            str(record.get("not_before") or ""),
            str(record.get("not_after") or ""),
            "|".join(record_dns_names(record)),
        )
        key = "\x1f".join(key_parts)
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return result


def public_result(spec: ProviderSpec, domain: str, endpoint: str) -> ProviderResult:
    return ProviderResult(
        provider=spec.name,
        provider_slug=spec.slug,
        domain=domain,
        status="not_found",
        query_supported=True,
        mode=spec.mode,
        authentication=spec.auth,
        endpoint=endpoint,
        notes=[spec.limitation],
    )


def query_certkit(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    endpoint = "https://ct.certkit.io/search"
    result = public_result(spec, domain, endpoint)
    session = create_session()
    response = request_with_retry(
        session,
        "POST",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        headers={"Content-Type": "application/json", "Origin": "https://www.certkit.io"},
        json={"domain": domain, "limit": min(limit, 100), "sort": "NotBeforeDesc"},
    )
    result.http_status = response.status_code
    require_success(response)
    payload = response.json()
    records = []
    for item in payload.get("results") or []:
        records.append(
            {
                "id": item.get("serialNumber"),
                "serial": item.get("serialNumber"),
                "common_name": item.get("commonName"),
                "dns_names": item.get("dnsNames") or [],
                "issuer": item.get("issuerOrganization") or item.get("issuerCommonName"),
                "not_before": item.get("notBefore"),
                "not_after": item.get("notAfter"),
                "logged_at": item.get("insertedTime"),
                "precertificate": item.get("isPrecert"),
            }
        )
    result.source_total = payload.get("totalCount")
    if not include_subdomains:
        result.notes.append(
            "The public endpoint searches child domains too; exact counts are filtered locally."
        )
    return classify_records(result, records, domain, include_subdomains, limit)


def query_certspotter(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    endpoint = "https://api.certspotter.com/v1/issuances"
    result = public_result(spec, domain, endpoint)
    session = create_session()
    api_key = os.getenv("CERTSPOTTER_API_KEY")
    if api_key:
        session.headers["Authorization"] = f"Bearer {api_key}"
        result.authentication = "CERTSPOTTER_API_KEY (authenticated)"
    params = [
        ("domain", domain),
        ("include_subdomains", str(include_subdomains).lower()),
        ("match_wildcards", "true"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params=params,
    )
    result.http_status = response.status_code
    require_success(response)
    payload = response.json()
    records = []
    for item in payload:
        issuer = item.get("issuer") or {}
        records.append(
            {
                "id": item.get("id"),
                "serial": item.get("serial_number"),
                "certificate_sha256": item.get("cert_sha256"),
                "dns_names": item.get("dns_names") or [],
                "issuer": issuer.get("name") if isinstance(issuer, dict) else issuer,
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
                "precertificate": item.get("precert"),
            }
        )
    result.source_total = len(records)
    result.notes.append("This quick test reads one API page; use the existing detailed Cert Spotter script for pagination.")
    return classify_records(result, records, domain, include_subdomains, limit)


def query_crtsh(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    endpoint = "https://crt.sh/"
    result = public_result(spec, domain, endpoint)
    query = f"%.{domain}" if include_subdomains else domain
    session = create_session()
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=max(timeout, 60.0),
        retries=retries,
        params={"q": query, "output": "json"},
    )
    result.http_status = response.status_code
    require_success(response)
    payload = response.json()
    records = []
    for item in payload:
        names = str(item.get("name_value") or "").splitlines()
        if item.get("common_name"):
            names.append(item["common_name"])
        records.append(
            {
                "id": item.get("id") or item.get("min_cert_id"),
                "serial": item.get("serial_number"),
                "common_name": item.get("common_name"),
                "dns_names": unique_strings(names),
                "issuer": item.get("issuer_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
                "logged_at": item.get("entry_timestamp"),
            }
        )
    records = deduplicate_records(records)
    result.source_total = len(records)
    result.notes.append("crt.sh's JSON endpoint is public but does not publish a formal SLA.")
    return classify_records(result, records, domain, include_subdomains, limit)


def query_ctlogs_dev(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    endpoint = "https://ctlogs.dev/search"
    result = public_result(spec, domain, endpoint)
    query = f"*.{domain}" if include_subdomains else domain
    session = create_session()
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={"q": query},
    )
    result.http_status = response.status_code
    require_success(response)
    html = response.text
    records = []
    rows = re.findall(r"<tr[^>]*>([\s\S]*?)</tr>", html, flags=re.IGNORECASE)
    for row in rows:
        cells = re.findall(r"<td[^>]*>([\s\S]*?)</td>", row, flags=re.IGNORECASE)
        if len(cells) < 6:
            continue
        href_match = re.search(r'href="([^"]+/cert/[^"/]+|/cert/[^"/]+)"', row)
        start_match = re.search(r'title="from\s+([^"]+)"', row, flags=re.IGNORECASE)
        matched_name = text_from_html(cells[0])
        cert_url = None
        cert_id = None
        if href_match:
            href = href_match.group(1)
            cert_url = f"https://ctlogs.dev{href}" if href.startswith("/") else href
            cert_id = href.rstrip("/").rsplit("/", 1)[-1]
        records.append(
            {
                "id": cert_id,
                "dns_names": [matched_name],
                "issuer": text_from_html(cells[3]),
                "not_before": start_match.group(1) if start_match else None,
                "not_after": text_from_html(cells[1]),
                "algorithm": text_from_html(cells[4]),
                "san_count": text_from_html(cells[5]),
                "certificate_url": cert_url,
            }
        )
    total_match = re.search(r"<b>([\d,]+)</b>\s+results", html, flags=re.IGNORECASE)
    result.source_total = int(total_match.group(1).replace(",", "")) if total_match else len(records)
    result.notes.append("ctlogs.dev exposes a public HTML search, not a documented JSON API.")
    return classify_records(result, records, domain, include_subdomains, limit)


def query_certobserver(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    endpoint = "https://certobserver.com/ct-search"
    result = public_result(spec, domain, endpoint)
    scope = "dns-host-and-subdomains" if include_subdomains else "dns-san-exact"
    session = create_session()
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={
            "q": domain,
            "scope": scope,
            "group": "san-set",
            "sort": "recently-logged",
            "includeExpired": "28d",
        },
    )
    result.http_status = response.status_code
    require_success(response)
    html = response.text
    records: list[dict[str, Any]] = []
    sections = re.findall(
        r'<section[^>]*class="[^"]*result-group[^"]*"[^>]*>([\s\S]*?)</section>',
        html,
        flags=re.IGNORECASE,
    )
    for section in sections:
        sans = [
            text_from_html(value)
            for value in re.findall(
                r'<span[^>]*class="[^"]*san-pill[^"]*"[^>]*>([\s\S]*?)</span>',
                section,
                flags=re.IGNORECASE,
            )
        ]
        for row in re.findall(
            r'<tr[^>]*class="[^"]*certificate-row[^"]*"[^>]*>([\s\S]*?)</tr>',
            section,
            flags=re.IGNORECASE,
        ):
            def cell(label: str) -> str | None:
                match = re.search(
                    rf'<td[^>]*data-label="{re.escape(label)}"[^>]*>([\s\S]*?)</td>',
                    row,
                    flags=re.IGNORECASE,
                )
                return text_from_html(match.group(1)) if match else None

            records.append(
                {
                    "id": cell("Serial"),
                    "serial": cell("Serial"),
                    "dns_names": unique_strings(sans),
                    "issuer": cell("Issuer organization"),
                    "logged_at": cell("Logged at (UTC)"),
                    "not_after": cell("Valid until (UTC)"),
                }
            )
    result.source_total = len(records)
    result.notes.append("Public search covers active certificates and at most the past 28 days of expired certificates.")
    return classify_records(result, records, domain, include_subdomains, limit)


def query_hurricane_electric(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    endpoint = "https://bgp.he.net/certs/api/domain"
    result = public_result(spec, domain, endpoint)
    session = create_session()
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={
            "domain": domain,
            "include_subdomains": str(include_subdomains).lower(),
            "page": 1,
        },
    )
    result.http_status = response.status_code
    require_success(response)
    payload = response.json()
    records = []
    for item in payload.get("certificates") or []:
        names = []
        for san in item.get("subject_alternative_names") or []:
            if isinstance(san, dict) and str(san.get("type", "")).upper() == "DNS":
                names.append(san.get("value"))
        records.append(
            {
                "id": item.get("id"),
                "serial": item.get("serial"),
                "dns_names": unique_strings(names),
                "subject": item.get("subject"),
                "issuer": item.get("issuer"),
                "not_before": item.get("notbefore"),
                "not_after": item.get("notafter"),
                "logged_at_epoch_ms": item.get("timestamp"),
                "precertificate": item.get("pre_cert"),
                "ct_logs": item.get("shards") or [],
            }
        )
    pagination = payload.get("pagination") or {}
    result.source_total = pagination.get("total_certificates", len(records))
    if pagination.get("total_pages", 1) > 1:
        result.notes.append("Only the first Hurricane Electric result page was read by this quick test.")
    result.notes.append("This JSON endpoint backs the public search UI but is not documented as a stable API.")
    return classify_records(result, records, domain, include_subdomains, limit)


NAME_KEYS = {
    "dns_names",
    "dnsnames",
    "names",
    "sans",
    "subject_alternative_names",
    "hostname",
    "host",
    "matchedhosts",
    "matchedwildcardhosts",
}


def strings_from_value(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict) and isinstance(item.get("value"), str):
                result.append(item["value"])
        return result
    return []


def generic_records(payload: Any) -> list[dict[str, Any]]:
    """Best-effort normalization for authenticated account APIs."""

    candidates: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            lowered = {str(key).lower().replace("-", "_"): item for key, item in value.items()}
            has_names = any(key in NAME_KEYS for key in lowered)
            has_cert_fields = any(
                key in lowered
                for key in ("serial", "serial_number", "sha256", "notbefore", "not_before", "notafter", "not_after")
            )
            if has_names or has_cert_fields:
                candidates.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    records: list[dict[str, Any]] = []
    for item in candidates:
        lowered = {str(key).lower().replace("-", "_"): value for key, value in item.items()}
        names: list[str] = []
        for key, value in lowered.items():
            if key in NAME_KEYS:
                names.extend(strings_from_value(value))
        common_name = lowered.get("common_name") or lowered.get("subject_common_name")
        if isinstance(common_name, str):
            names.append(common_name)
        records.append(
            {
                "id": lowered.get("id") or lowered.get("sha256") or lowered.get("fingerprint"),
                "serial": lowered.get("serial") or lowered.get("serial_number"),
                "common_name": common_name,
                "dns_names": unique_strings(names),
                "issuer": lowered.get("issuer") or lowered.get("issuer_name") or lowered.get("issuerca"),
                "not_before": lowered.get("not_before") or lowered.get("notbefore"),
                "not_after": lowered.get("not_after") or lowered.get("notafter"),
                "first_seen": lowered.get("first_seen") or lowered.get("firstseen"),
            }
        )
    return deduplicate_records(records)


def query_censys(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    if missing_environment(spec.required_env):
        return credential_result(spec, domain)
    endpoint = "https://api.platform.censys.io/v3/global/search/query"
    result = public_result(spec, domain, endpoint)
    result.mode = spec.mode
    result.authentication = spec.auth
    token = os.environ["CENSYS_API_TOKEN"]
    organization_id = os.environ["CENSYS_ORGANIZATION_ID"]
    session = create_session()
    session.headers["Authorization"] = f"Bearer {token}"
    response = request_with_retry(
        session,
        "POST",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={"organization_id": organization_id},
        json={"query": json.dumps(domain), "page_size": min(limit, 100)},
    )
    result.http_status = response.status_code
    require_success(response)
    payload = response.json()
    records = generic_records(payload)
    result.source_total = len(records)
    result.notes.append("Censys Free accounts cannot use search; a paid search-capable plan is required.")
    return classify_records(result, records, domain, include_subdomains, limit)


def query_merklemap(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    if missing_environment(spec.required_env):
        return credential_result(spec, domain)
    endpoint = "https://api.merklemap.com/v1/search"
    result = public_result(spec, domain, endpoint)
    result.mode = spec.mode
    result.authentication = spec.auth
    session = create_session()
    session.headers["Authorization"] = f"Bearer {os.environ['MERKLEMAP_API_TOKEN']}"
    query = f"*.{domain}" if include_subdomains else f"={domain}"
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={"query": query, "type": "wildcard", "page": 0},
    )
    result.http_status = response.status_code
    require_success(response)
    payload = response.json()
    records = []
    for item in payload.get("results") or []:
        records.append(
            {
                "id": item.get("id"),
                "common_name": item.get("subject_common_name"),
                "dns_names": unique_strings([item.get("hostname"), item.get("subject_common_name")]),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
                "first_seen": item.get("first_seen"),
            }
        )
    result.source_total = payload.get("count", len(records))
    result.notes.append("Only API page 0 is read by this quick test.")
    return classify_records(result, records, domain, include_subdomains, limit)


def query_hardenize(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    if missing_environment(spec.required_env):
        return credential_result(spec, domain)
    org = quote(os.environ["HARDENIZE_ORG"], safe="")
    endpoint = f"https://api.hardenize.com/v1/org/{org}/certs/summaries"
    result = public_result(spec, domain, endpoint)
    result.mode = spec.mode
    result.authentication = spec.auth
    session = create_session()
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        auth=(os.environ["HARDENIZE_API_USERNAME"], os.environ["HARDENIZE_API_PASSWORD"]),
        params={"host": domain},
    )
    result.http_status = response.status_code
    require_success(response)
    records = generic_records(response.json())
    result.source_total = len(records)
    return classify_records(result, records, domain, include_subdomains, limit)


def red_sift_authorization(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("api-key ", "bearer ")):
        return value
    return f"Api-Key {value}"


def query_red_sift(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    if missing_environment(spec.required_env):
        return credential_result(spec, domain)
    endpoint = "https://rpc.redsift.cloud/hardenize/certs"
    result = public_result(spec, domain, endpoint)
    result.mode = spec.mode
    result.authentication = spec.auth
    session = create_session()
    session.headers["Authorization"] = red_sift_authorization(os.environ["REDSIFT_API_KEY"])
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={"host": domain},
    )
    result.http_status = response.status_code
    require_success(response)
    records = generic_records(response.json())
    result.source_total = len(records)
    return classify_records(result, records, domain, include_subdomains, limit)


def query_oh_dear(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    if missing_environment(spec.required_env):
        return credential_result(spec, domain)
    monitor_id = quote(os.environ["OHDEAR_MONITOR_ID"], safe="")
    monitor_endpoint = f"https://ohdear.app/api/monitors/{monitor_id}"
    endpoint = f"{monitor_endpoint}/detected-certificates"
    result = public_result(spec, domain, endpoint)
    result.mode = spec.mode
    result.authentication = spec.auth
    session = create_session()
    session.headers["Authorization"] = f"Bearer {os.environ['OHDEAR_TOKEN']}"
    monitor_response = request_with_retry(
        session,
        "GET",
        monitor_endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
    )
    require_success(monitor_response)
    monitor_payload = monitor_response.json()
    monitor_value = monitor_payload.get("url") or monitor_payload.get("hostname") or ""
    monitor_host = normalize_dns_name(urlparse(monitor_value if "://" in monitor_value else f"//{monitor_value}").hostname or "")
    if monitor_host != domain:
        result.status = "configuration_mismatch"
        result.notes.append(f"OHDEAR_MONITOR_ID belongs to {monitor_host or 'an unknown host'}, not {domain}.")
        return result
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
    )
    result.http_status = response.status_code
    require_success(response)
    records = generic_records(response.json())
    result.source_total = len(records)
    return classify_records(result, records, domain, include_subdomains, limit)


def query_report_uri(
    spec: ProviderSpec,
    domain: str,
    include_subdomains: bool,
    limit: int,
    timeout: float,
    retries: int,
    reporter: Reporter,
) -> ProviderResult:
    if missing_environment(spec.required_env):
        return credential_result(spec, domain)
    endpoint = "https://api.report-uri.com/v1/reports/certificate_transparency"
    result = public_result(spec, domain, endpoint)
    result.mode = spec.mode
    result.authentication = spec.auth
    session = create_session()
    session.headers["Authorization"] = f"Bearer {os.environ['REPORT_URI_API_KEY']}"
    response = request_with_retry(
        session,
        "GET",
        endpoint,
        reporter,
        timeout=timeout,
        retries=retries,
        params={
            "unit": "months",
            "date": datetime.now(timezone.utc).strftime("%Y-%m"),
            "hostnames": domain,
        },
    )
    result.http_status = response.status_code
    require_success(response)
    records = generic_records(response.json())
    result.source_total = len(records)
    result.notes.append("This reads only the current month's reports for domains configured in the account.")
    return classify_records(result, records, domain, include_subdomains, limit)


PROVIDERS: dict[str, ProviderSpec] = {
    "censys": ProviderSpec(
        "censys",
        "Censys",
        "authenticated_global_search",
        "Personal Access Token; search requires a paid search-capable plan",
        "https://docs.censys.com/reference/v3-globaldata-search-query",
        "The Platform API can search certificate names globally, but Free accounts only have lookup access.",
        ("CENSYS_API_TOKEN", "CENSYS_ORGANIZATION_ID"),
    ),
    "certkit": ProviderSpec(
        "certkit",
        "CertKit",
        "public_web_search",
        "No key for the public tool; Business account for supported API access",
        "https://www.certkit.io/tools/ct-logs/",
        "The public web endpoint returns at most 100 certificates and is rate limited.",
    ),
    "certobserver": ProviderSpec(
        "certobserver",
        "CertObserver",
        "public_web_search",
        "No key",
        "https://certobserver.com/ct-search",
        "The public search is server-rendered HTML and focuses on unexpired/recently expired certificates.",
    ),
    "cloudflare": ProviderSpec(
        "cloudflare",
        "Cloudflare",
        "zone_monitoring_only",
        "Cloudflare API token for configuring alerts, but no certificate-result search endpoint",
        "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/certificate-transparency-monitoring/",
        "Cloudflare CT Monitoring sends alerts for zones in your account; its API only gets or changes alert settings.",
    ),
    "crtsh": ProviderSpec(
        "crtsh",
        "crt.sh",
        "public_global_search",
        "No key",
        "https://crt.sh/",
        "Public global historical search; the JSON interface has no formal service-level guarantee.",
    ),
    "ctlogs_dev": ProviderSpec(
        "ctlogs_dev",
        "ctlogs.dev",
        "public_global_search",
        "No key",
        "https://ctlogs.dev/",
        "Public global historical search is available through an HTML result page.",
    ),
    "digicert": ProviderSpec(
        "digicert",
        "DigiCert",
        "customer_domain_monitoring_only",
        "DigiCert account/product entitlement required",
        "https://docs.digicert.com/en/certcentral/monitor-certificates--generate-reports--and-maintain-compliance/ct-log-monitoring-service.html",
        "CT monitoring is limited to domains on eligible Secure Site Pro orders or configured Trust Lifecycle Manager inventory; it is not an arbitrary-domain search API.",
    ),
    "keytos": ProviderSpec(
        "keytos",
        "Keytos EZMonitor",
        "customer_domain_monitoring_only",
        "EZMonitor account required; no public domain-search API documented",
        "https://www.keytos.io/how-ezmonitor-monitors-certificate-transparency-logs",
        "EZMonitor indexes CT data for domains in a customer's monitored inventory, not public one-off domain searches.",
    ),
    "hardenize": ProviderSpec(
        "hardenize",
        "Hardenize",
        "authenticated_account_inventory",
        "Organization-scoped HTTP Basic API credentials",
        "https://www.hardenize.com/docs/api/v1/",
        "The host filter searches certificates already imported into your Hardenize organization, not the global CT index.",
        ("HARDENIZE_ORG", "HARDENIZE_API_USERNAME", "HARDENIZE_API_PASSWORD"),
    ),
    "hurricane_electric": ProviderSpec(
        "hurricane_electric",
        "Hurricane Electric",
        "public_global_search",
        "No key",
        "https://bgp.he.net/certs",
        "The public UI has a JSON backing endpoint, but Hurricane Electric does not document it as a stable API.",
    ),
    "merklemap": ProviderSpec(
        "merklemap",
        "MerkleMap",
        "authenticated_global_search",
        "Bearer API token",
        "https://www.merklemap.com/documentation/search",
        "The documented global search API requires a MerkleMap API token.",
        ("MERKLEMAP_API_TOKEN",),
    ),
    "oh_dear": ProviderSpec(
        "oh_dear",
        "Oh Dear",
        "authenticated_monitor_inventory",
        "Bearer token and an existing monitor ID",
        "https://ohdear.app/docs/api/introduction/swagger",
        "Detected certificates can be listed only for a monitor already present in your Oh Dear account.",
        ("OHDEAR_TOKEN", "OHDEAR_MONITOR_ID"),
    ),
    "red_sift": ProviderSpec(
        "red_sift",
        "Red Sift Certificates",
        "authenticated_account_inventory",
        "Red Sift API key",
        "https://docs.redsift.com/reference/listcertificates",
        "The API lists certificates in your Red Sift Certificates inventory; Lite accounts support selected certificate endpoints.",
        ("REDSIFT_API_KEY",),
    ),
    "report_uri": ProviderSpec(
        "report_uri",
        "Report URI",
        "authenticated_account_reports",
        "Report URI API key",
        "https://docs.report-uri.com/integrations/api/",
        "The API returns CT reports collected for domains configured in your account, not a global historical search.",
        ("REPORT_URI_API_KEY",),
    ),
    "sslmate_certspotter": ProviderSpec(
        "sslmate_certspotter",
        "SSLMate Cert Spotter",
        "public_global_search",
        "No key for evaluation; CERTSPOTTER_API_KEY for production quota",
        "https://sslmate.com/certspotter/api/",
        "The issuance search API returns unexpired certificate issuances only.",
    ),
    "stellastra": ProviderSpec(
        "stellastra",
        "Stellastra",
        "customer_domain_monitoring_only",
        "Commercial account/API integration arranged with Stellastra",
        "https://stellastra.com/solution/certificate-transparency-log-monitor",
        "Stellastra advertises API/SIEM integration for monitored customer environments but publishes no arbitrary-domain search API.",
    ),
}


Handler = Callable[
    [ProviderSpec, str, bool, int, float, int, Reporter], ProviderResult
]

HANDLERS: dict[str, Handler] = {
    "censys": query_censys,
    "certkit": query_certkit,
    "certobserver": query_certobserver,
    "crtsh": query_crtsh,
    "ctlogs_dev": query_ctlogs_dev,
    "hardenize": query_hardenize,
    "hurricane_electric": query_hurricane_electric,
    "merklemap": query_merklemap,
    "oh_dear": query_oh_dear,
    "red_sift": query_red_sift,
    "report_uri": query_report_uri,
    "sslmate_certspotter": query_certspotter,
}


def execute_provider(
    provider_slug: str,
    domain: str,
    *,
    include_subdomains: bool = False,
    limit: int = 50,
    timeout: float = 60.0,
    retries: int = 3,
    log_file: Path | None = None,
    console: bool = True,
    console_records: bool = True,
) -> ProviderResult:
    load_environment()
    normalized_domain = normalize_domain(domain)
    if provider_slug not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider_slug}")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if retries < 1:
        raise ValueError("retries must be at least 1")

    spec = PROVIDERS[provider_slug]
    path = (log_file or default_log_path(provider_slug, normalized_domain)).resolve()
    reporter = Reporter(path, console=console)
    started = time.perf_counter()
    try:
        reporter.line(f"=== {spec.name} CT Monitor Test ===")
        reporter.line(f"Domain: {normalized_domain}")
        reporter.line(f"Include subdomains: {include_subdomains}")
        reporter.line(f"Mode: {spec.mode}")
        reporter.line(f"Authentication: {spec.auth}")
        reporter.line(f"Official reference: {spec.docs_url}")
        reporter.line(f"Log file: {path}")
        reporter.line()

        handler = HANDLERS.get(provider_slug)
        if handler is None:
            result = unsupported_result(spec, normalized_domain)
        else:
            result = handler(
                spec,
                normalized_domain,
                include_subdomains,
                limit,
                timeout,
                retries,
                reporter,
            )
    except Exception as exc:  # A standalone diagnostic must always leave a log.
        result = ProviderResult(
            provider=spec.name,
            provider_slug=spec.slug,
            domain=normalized_domain,
            status="error",
            query_supported=provider_slug in HANDLERS,
            mode=spec.mode,
            authentication=spec.auth,
            error=f"{type(exc).__name__}: {exc}",
            notes=[spec.limitation],
        )

    result.elapsed_seconds = round(time.perf_counter() - started, 3)
    result.log_file = str(path)
    reporter.line()
    reporter.line(f"Status: {result.status}")
    reporter.line(f"Query supported: {result.query_supported}")
    reporter.line(f"HTTP status: {result.http_status}")
    reporter.line(f"Source total: {result.source_total}")
    reporter.line(f"Returned records: {result.returned_records}")
    reporter.line(f"Exact DNS-name matches: {result.exact_matches}")
    reporter.line(f"In-scope matches: {result.in_scope_matches}")
    reporter.line(f"Elapsed: {result.elapsed_seconds:.3f}s")
    if result.required_env:
        reporter.line(f"Required environment variables: {', '.join(result.required_env)}")
    for note in result.notes:
        reporter.line(f"Note: {note}")
    if result.error:
        reporter.line(f"Error: {result.error}")
    if result.records:
        reporter.line()
        reporter.line(f"Normalized records (up to {limit}):", console=console_records)
        for record in result.records:
            reporter.json(record, console=console_records)
    reporter.line()
    reporter.line(
        "RESULT_JSON=" + json.dumps(result.summary_dict(), ensure_ascii=False, sort_keys=True)
    )
    reporter.close()
    return result


def build_provider_parser(spec: ProviderSpec) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Test {spec.name} against a Certificate Transparency domain query."
    )
    parser.add_argument("domain", nargs="?", default=DEFAULT_DOMAIN)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--log-file", type=Path)
    return parser


def result_exit_code(result: ProviderResult) -> int:
    if result.status == "error":
        return 1
    if result.status == "credentials_required":
        return 2
    if result.status == "no_equivalent_domain_search":
        return 3
    if result.status == "configuration_mismatch":
        return 4
    return 0


def run_provider_cli(provider_slug: str) -> int:
    spec = PROVIDERS[provider_slug]
    args = build_provider_parser(spec).parse_args()
    try:
        result = execute_provider(
            provider_slug,
            args.domain,
            include_subdomains=args.include_subdomains,
            limit=args.limit,
            timeout=args.timeout,
            retries=args.retries,
            log_file=args.log_file,
        )
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 1
    return result_exit_code(result)


def run_all_cli() -> int:
    parser = argparse.ArgumentParser(
        description="Run all services from certificate.transparency.dev/monitors."
    )
    parser.add_argument("domain", nargs="?", default=DEFAULT_DOMAIN)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--providers",
        help="Comma-separated provider slugs; default is all providers.",
    )
    args = parser.parse_args()
    domain = normalize_domain(args.domain)
    selected = list(PROVIDERS)
    if args.providers:
        selected = [item.strip() for item in args.providers.split(",") if item.strip()]
        unknown = [item for item in selected if item not in PROVIDERS]
        if unknown:
            parser.error(f"unknown provider(s): {', '.join(unknown)}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = (LOG_DIR / f"summary_{safe_name(domain)}_{timestamp}.log").resolve()
    summary = Reporter(summary_path)
    summary.line("=== Certificate Transparency Monitor Comparison ===")
    summary.line(f"Domain: {domain}")
    summary.line(f"Providers: {len(selected)}")
    summary.line(f"Summary log: {summary_path}")
    summary.line()

    results: list[ProviderResult] = []
    for index, slug in enumerate(selected, start=1):
        spec = PROVIDERS[slug]
        summary.line(f"[{index}/{len(selected)}] {spec.name}")
        result = execute_provider(
            slug,
            domain,
            include_subdomains=args.include_subdomains,
            limit=args.limit,
            timeout=args.timeout,
            retries=args.retries,
            console=False,
            console_records=False,
        )
        results.append(result)
        summary.line(
            f"  status={result.status} exact={result.exact_matches} "
            f"returned={result.returned_records} log={result.log_file}"
        )

    summary.line()
    summary.line("=== Summary JSON ===")
    for result in results:
        summary.json(result.summary_dict())
    summary.close()

    errors = [result for result in results if result.status == "error"]
    found = [result.provider for result in results if result.status == "found_exact"]
    credentials = [
        result.provider for result in results if result.status == "credentials_required"
    ]
    unsupported = [
        result.provider
        for result in results
        if result.status == "no_equivalent_domain_search"
    ]
    print()
    print(f"Exact match found by: {', '.join(found) if found else 'none'}")
    print(f"Credentials required: {', '.join(credentials) if credentials else 'none'}")
    print(f"No equivalent search API: {', '.join(unsupported) if unsupported else 'none'}")
    print(f"Errors: {', '.join(item.provider for item in errors) if errors else 'none'}")
    print(f"Summary log: {summary_path}")
    return 1 if errors else 0
