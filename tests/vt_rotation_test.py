"""
VirusTotal API Key Rotation Test

Purpose:
  Actively exercise the VirusTotalScanner key rotation logic.
Modes:
  1. live  : Perform real queries against VT (default small domain set)
  2. simulate: Monkey-patch requests.get to emulate 200/429 patterns without hitting network

Features:
  - Shows which key index is used for every request
  - Forces multiple sequential 429 responses to verify full-cycle cooldown logic
  - Summarizes per-key usage counts, 429 hit counts, switches, and final state

Usage:
  python vt_rotation_test.py --keys key1,key2[,key3] [--domain example.com] [--mode live|simulate] [--max-pages 3]

NOTE: Avoid large page counts in live mode to respect public VT rate limits.
"""
from __future__ import annotations
import argparse
import time
import random
from typing import List, Dict, Any

import requests

from scanners.virustotal_scanner import VirusTotalScanner
from utils.logger import get_logger

logger = get_logger("vt_rotation_test")

class RotationObserver:
    def __init__(self, scanner: VirusTotalScanner):
        self.scanner = scanner
        self.events: List[Dict[str, Any]] = []
        self.key_use_count: Dict[int, int] = {}
        self.key_429_count: Dict[int, int] = {}
        self.switch_events: int = 0
        # Inject wrappers
        orig_get = requests.get

        def wrapped_get(url, *a, **kw):
            key_idx = scanner._key_index  # noqa: SLF001 (internal access for diagnostic)
            self.key_use_count[key_idx] = self.key_use_count.get(key_idx, 0) + 1
            start = time.time()
            resp = orig_get(url, *a, **kw)
            elapsed = time.time() - start
            if resp.status_code == 429:
                self.key_429_count[key_idx] = self.key_429_count.get(key_idx, 0) + 1
            self.events.append({
                't': time.strftime('%H:%M:%S'),
                'key_index': key_idx,
                'status': resp.status_code,
                'elapsed': round(elapsed, 2),
                'url': url
            })
            return resp

        self._orig_get = orig_get
        self._wrapped_get = wrapped_get

    def enable(self):
        requests.get = self._wrapped_get  # type: ignore

    def disable(self):
        requests.get = self._orig_get  # type: ignore

    def note_switch(self):
        self.switch_events += 1


def patch_scanner_logging(scanner: VirusTotalScanner, observer: RotationObserver):
    orig_set_key = scanner._set_key  # noqa: SLF001

    def patched_set_key(idx: int):  # noqa: ANN001
        observer.note_switch()
        logger.info(f"[TEST] Switching to key index {idx}")
        return orig_set_key(idx)

    scanner._set_key = patched_set_key  # type: ignore


def simulate_mode(keys: List[str], pages: int, pattern: str):
    """Simulate rotation without real API calls.

    pattern syntax examples:
      '3OK,2RL' -> 3 successes then 2 rate limits repeating
      '1RL,1OK' -> alternate 429 / 200
    """
    # Build response sequence chunk
    seq: List[str] = []
    for token in pattern.split(','):
        token = token.strip().upper()
        if token.endswith('OK'):
            n = int(token[:-2]) if token[:-2] else 1
            seq.extend(['OK'] * n)
        elif token.endswith('RL'):
            n = int(token[:-2]) if token[:-2] else 1
            seq.extend(['RL'] * n)
        else:
            raise ValueError(f"Bad pattern token: {token}")
    if not seq:
        raise ValueError("Empty simulation sequence")

    class FakeResp:
        def __init__(self, status_code: int, data: dict):
            self.status_code = status_code
            self._data = data
        def json(self):  # noqa: D401
            return self._data

    # Monkey patch
    call_counter = {'i': 0}
    orig_get = requests.get

    def fake_get(url, headers=None, params=None, timeout=30):  # noqa: D401
        i = call_counter['i']
        sym = seq[i % len(seq)]
        call_counter['i'] += 1
        if sym == 'OK':
            # fabricate up to 2 subdomains per call to advance paging
            subs = [f"sub{i}-{k}.example.com" for k in range(random.randint(1, 2))]
            data = {
                'data': [{'id': s} for s in subs],
                'links': {'next': f"https://api.fake/?cursor={call_counter['i']}" if call_counter['i'] < pages else None}
            }
            return FakeResp(200, data)
        else:
            return FakeResp(429, {})

    try:
        requests.get = fake_get  # type: ignore
        scanner = VirusTotalScanner(keys)
        # Speed up params
        scanner.per_page_sleep = 0.1
        scanner.rotate_wait_seconds = 0.05
        scanner.full_cycle_cooldown = 0.2
        observer = RotationObserver(scanner)
        patch_scanner_logging(scanner, observer)
        observer.enable()
        res = scanner.get_subdomains('example.com')
    finally:
        requests.get = orig_get  # type: ignore
    return {
        'subdomains_found': len(res),
        'events': observer.events,
        'key_use': observer.key_use_count,
        'key_429': observer.key_429_count,
        'switches': observer.switch_events
    }


def live_mode(keys: List[str], domain: str, max_pages: int):
    scanner = VirusTotalScanner(keys)
    # Tighten waits just for test (still keep some delay)
    scanner.per_page_sleep = 5
    scanner.rotate_wait_seconds = 2
    scanner.full_cycle_cooldown = 30

    observer = RotationObserver(scanner)
    patch_scanner_logging(scanner, observer)
    observer.enable()

    collected: List[str] = []
    try:
        logger.info(f"[TEST] Live mode start domain={domain} max_pages={max_pages}")
        url_pages = 0
        url_pages_target = max_pages
        # We mimic get_subdomains logic but with page cap
        from urllib.parse import urlparse, parse_qs
        base_url = f"{scanner.BASE_URL}/domains/{domain}/subdomains"
        cursor = None
        page = 1
        keys_429_in_cycle = set()
        while True:
            params = {'limit': 40}
            if cursor:
                params['cursor'] = cursor
            try:
                resp = requests.get(base_url, headers=scanner.headers, params=params, timeout=30)
                key_idx = scanner._key_index
                if resp.status_code == 200:
                    keys_429_in_cycle.clear()
                    data = resp.json()
                    page_subs = []
                    for item in data.get('data', []):
                        sid = item.get('id', '').strip()
                        if sid and sid not in collected:
                            collected.append(sid)
                            page_subs.append(sid)
                    logger.info(f"[TEST] Page {page} key#{key_idx+1} got {len(page_subs)} new (total={len(collected)})")
                    next_link = data.get('links', {}).get('next')
                    if not next_link:
                        break
                    parsed = urlparse(next_link)
                    new_cursor = parse_qs(parsed.query).get('cursor', [None])[0]
                    if not new_cursor or new_cursor == cursor:
                        break
                    cursor = new_cursor
                    page += 1
                    url_pages += 1
                    if url_pages >= url_pages_target:
                        logger.info('[TEST] Reached max test pages cap, stopping.')
                        break
                    time.sleep(scanner.per_page_sleep)
                elif resp.status_code == 429:
                    logger.warning(f"[TEST] 429 on page {page} using key#{key_idx+1}")
                    keys_429_in_cycle.add(key_idx)
                    if scanner._next_key():
                        time.sleep(scanner.rotate_wait_seconds)
                        continue
                    else:
                        if len(keys_429_in_cycle) == len(scanner.api_keys):
                            logger.warning(f"[TEST] All keys 429, cooling {scanner.full_cycle_cooldown}s")
                            time.sleep(scanner.full_cycle_cooldown)
                            keys_429_in_cycle.clear()
                            continue
                        else:
                            logger.error('[TEST] Unexpected rotation condition, stopping.')
                            break
                else:
                    logger.error(f"[TEST] HTTP {resp.status_code} abort")
                    break
            except Exception as e:  # noqa: BLE001
                logger.error(f"[TEST] Error: {e}")
                break
    finally:
        observer.disable()

    return {
        'subdomains_found': len(collected),
        'key_use': observer.key_use_count,
        'key_429': observer.key_429_count,
        'switches': observer.switch_events
    }


def summarize(result: Dict[str, Any]):
    print('\n=== Rotation Summary ===')
    print(f"Subdomains gathered: {result.get('subdomains_found')}")
    ku = result.get('key_use', {})
    k429 = result.get('key_429', {})
    for idx in sorted(ku.keys()):
        print(f"Key#{idx+1}: used {ku[idx]} times, 429={k429.get(idx,0)}")
    print(f"Key switches: {result.get('switches')}")
    events = result.get('events')
    if events:
        print('\nFirst 15 events:')
        for ev in events[:15]:
            print(f"  {ev['t']} key#{ev['key_index']+1} status={ev['status']} elapsed={ev['elapsed']}s")


def parse_args():
    p = argparse.ArgumentParser(description='VirusTotal key rotation tester')
    # --keys 改為可選；未提供時自動從 config.py 讀取
    p.add_argument('--keys', required=False, help='Comma separated VT API keys (optional, falls back to config)')
    p.add_argument('--domain', default='example.com', help='Domain for live mode test')
    p.add_argument('--mode', choices=['live', 'simulate'], default='simulate')
    p.add_argument('--pattern', default='2OK,1RL', help='Simulation pattern (simulate mode)')
    p.add_argument('--max-pages', type=int, default=3, help='Max pages to fetch in live mode')
    return p.parse_args()


def main():
    args = parse_args()
    keys: List[str] = []
    if args.keys:
        keys = [k.strip() for k in args.keys.split(',') if k.strip()]
    else:
        # 從 config.py 載入多組 VT Keys
        try:
            from config import Config
            cfg = Config.from_env()
            keys = list(cfg.VIRUSTOTAL_API_KEYS)
        except Exception as e:  # noqa: BLE001
            raise SystemExit(f"Failed to load keys from config: {e}")

    if not keys:
        raise SystemExit('No VirusTotal API keys provided (neither --keys nor config)')

    if args.mode == 'simulate':
        logger.info(f"[TEST] Simulation mode pattern={args.pattern} keys={len(keys)} (from {'--keys' if args.keys else 'config'})")
        result = simulate_mode(keys, pages=args.max_pages, pattern=args.pattern)
    else:
        logger.info(f"[TEST] Live mode domain={args.domain} pages={args.max_pages} keys={len(keys)} (from {'--keys' if args.keys else 'config'})")
        result = live_mode(keys, args.domain, args.max_pages)
    summarize(result)

if __name__ == '__main__':
    main()
