"""
DNS Zone 掃描器
為每個 FQDN 找出 zone apex，並取得 SOA 與 NS 資訊。
"""

from __future__ import annotations

import random
import time
from typing import Dict, List, Optional

import dns.exception
import dns.resolver

from config import Config
from utils.logger import get_logger

logger = get_logger("scanners.dns_zone_scanner")


class DnsZoneScanner:
    """使用 dnspython 查詢 zone SOA/NS 的掃描器。"""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.max_retries = 3
        self.timeout = 3.0

    def _new_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        ns = [s.strip() for s in (self.config.DNS_SERVERS or []) if s and s.strip()]
        if ns:
            resolver.nameservers = ns
        return resolver

    def _backoff(self, attempt: int) -> None:
        delay = min(2.0, 0.3 * (2 ** max(0, attempt - 1))) + random.uniform(0.0, 0.15)
        time.sleep(delay)

    def _resolve_with_retry(self, resolver: dns.resolver.Resolver, name: str, rtype: str):
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return resolver.resolve(name, rtype, lifetime=self.timeout)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                raise
            except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.YXDOMAIN) as e:
                last_exc = e
                if attempt < self.max_retries:
                    self._backoff(attempt)
                continue
            except Exception as e:
                last_exc = e
                if attempt < self.max_retries:
                    self._backoff(attempt)
                continue
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected DNS resolve state")

    def _walk_candidates(self, fqdn: str) -> List[str]:
        labels = [p for p in fqdn.lower().strip(".").split(".") if p]
        candidates: List[str] = []
        for i in range(len(labels)):
            candidates.append(".".join(labels[i:]))
        return candidates

    def get_zone_info(self, fqdn: str) -> dict:
        """
        對單一 FQDN 查詢 zone apex、SOA 與 NS。

        Returns:
            dict with keys:
            - fqdn, zone_apex, status, error_message, matched_by,
              soa_*, ns_records(list[dict])
        """
        fqdn_norm = fqdn.lower().strip(".")
        if not fqdn_norm:
            return {
                "fqdn": fqdn,
                "zone_apex": None,
                "status": "error",
                "error_message": "empty fqdn",
                "matched_by": None,
                "ns_records": [],
            }

        resolver = self._new_resolver()
        candidates = self._walk_candidates(fqdn_norm)

        zone_apex: Optional[str] = None
        soa_data = {}
        matched_by: Optional[str] = None

        for idx, cand in enumerate(candidates):
            try:
                soa_answers = self._resolve_with_retry(resolver, cand, "SOA")
                if soa_answers:
                    soa = soa_answers[0]
                    zone_apex = cand
                    matched_by = "direct_soa" if idx == 0 else "soa_walk"
                    soa_data = {
                        "soa_mname": str(soa.mname).rstrip("."),
                        "soa_rname": str(soa.rname).rstrip("."),
                        "soa_serial": int(soa.serial),
                        "soa_refresh": int(soa.refresh),
                        "soa_retry": int(soa.retry),
                        "soa_expire": int(soa.expire),
                        "soa_minimum": int(soa.minimum),
                        "soa_ttl": int(getattr(soa_answers.rrset, "ttl", 0) or 0),
                    }
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                logger.debug(f"[DNS Zone] SOA 查詢失敗 {cand}: {e}")
                continue

        if not zone_apex:
            return {
                "fqdn": fqdn_norm,
                "zone_apex": None,
                "status": "no_soa",
                "error_message": "SOA not found by walk-up",
                "matched_by": None,
                "ns_records": [],
            }

        ns_records: List[dict] = []
        ns_status = "ok"
        ns_error = None
        try:
            ns_answers = self._resolve_with_retry(resolver, zone_apex, "NS")
            ttl = int(getattr(ns_answers.rrset, "ttl", 0) or 0)
            seen_ns: set[str] = set()
            for rr in ns_answers:
                ns_host = str(getattr(rr, "target", rr)).rstrip(".").lower()
                if ns_host and ns_host not in seen_ns:
                    seen_ns.add(ns_host)
                    ns_records.append({"ns_host": ns_host, "ns_ttl": ttl})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            ns_status = "no_ns"
            ns_error = "NS not found"
        except Exception as e:
            ns_status = "error"
            ns_error = str(e)

        return {
            "fqdn": fqdn_norm,
            "zone_apex": zone_apex,
            "status": ns_status if ns_status != "ok" else "ok",
            "error_message": ns_error,
            "matched_by": matched_by,
            "ns_records": ns_records,
            **soa_data,
        }

    def get_zone_info_batch(self, fqdns: List[str]) -> Dict[str, dict]:
        """
        批次查詢，內建 zone apex 快取，避免重複查同一 zone。
        """
        result: Dict[str, dict] = {}
        zone_cache: Dict[str, dict] = {}

        deduped = list(dict.fromkeys([f.strip().lower().strip(".") for f in fqdns if f and f.strip()]))
        for fqdn in deduped:
            info = self.get_zone_info(fqdn)
            zone_apex = info.get("zone_apex")

            if zone_apex and zone_apex in zone_cache:
                cached = zone_cache[zone_apex]
                result[fqdn] = {
                    **cached,
                    "fqdn": fqdn,
                    "matched_by": info.get("matched_by", "soa_walk"),
                }
                continue

            result[fqdn] = info
            if zone_apex:
                zone_cache[zone_apex] = {
                    "zone_apex": info.get("zone_apex"),
                    "status": info.get("status"),
                    "error_message": info.get("error_message"),
                    "ns_records": info.get("ns_records", []),
                    "soa_mname": info.get("soa_mname"),
                    "soa_rname": info.get("soa_rname"),
                    "soa_serial": info.get("soa_serial"),
                    "soa_refresh": info.get("soa_refresh"),
                    "soa_retry": info.get("soa_retry"),
                    "soa_expire": info.get("soa_expire"),
                    "soa_minimum": info.get("soa_minimum"),
                    "soa_ttl": info.get("soa_ttl"),
                }

        return result
