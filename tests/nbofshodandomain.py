#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

import shodan

# ---- 讀取 API Key：環境變數優先，其次 config.Config，最後才是 placeholder ----
try:
    from config import Config  # 可選
    _CFG_KEY = getattr(Config, "SHODAN_API_KEY", None)
except Exception:
    _CFG_KEY = None

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY") or _CFG_KEY or "YOUR_SHODAN_API_KEY"


# ---- Logger 設定：同時輸出到終端機與檔案 ----
def setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("shodan_domain_logger")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    # 檔案輸出（UTF-8）
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)

    # 終端機輸出
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)

    fmt = logging.Formatter("%(message)s")  # 簡潔格式
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ---- 抓取所有分頁並合併 ----
def fetch_all_pages(api: shodan.Shodan, domain: str, max_pages: Optional[int] = None) -> Dict[str, Any]:
    """
    連續呼叫 api.dns.domain_info(domain, page=1..N) 直到 more=False。
    會合併所有頁面的 subdomains 與 data，回傳合併後的 JSON dict。
    max_pages：可選，限制最多抓幾頁（以防意外燒太多點數）。
    """
    page = 1
    all_subdomains = set()
    all_data: List[Dict[str, Any]] = []
    last_info: Dict[str, Any] = {}

    while True:
        info = api.dns.domain_info(domain=domain, page=page)
        last_info = info  # 保留最後一頁（拿 tags 等非重點欄位）

        subs = info.get("subdomains", []) or []
        all_subdomains.update(subs)

        data_entries = info.get("data", []) or []
        all_data.extend(data_entries)

        if not info.get("more"):
            break

        page += 1
        if max_pages is not None and page > max_pages:
            break

    merged = {
        "domain": domain,
        "tags": last_info.get("tags", []),          # 取最後一頁的 tags（通常影響不大）
        "data": all_data,                           # 合併後的 data
        "subdomains": sorted(all_subdomains),       # 合併後的 subdomains
        "more": False
    }
    return merged


# ---- 從完整網域清單萃取「緊鄰 root 的次級網域」 ----
def extract_second_level_under_root(root: str, full_domains: List[str]) -> List[str]:
    """
    root='tn.edu.tw'
      'doc.ptivs.tn.edu.tw'  → 'ptivs.tn.edu.tw'
      'ad.tncvs.tn.edu.tw'   → 'tncvs.tn.edu.tw'
      'bookroom.tntcsh.tn.edu.tw' → 'tntcsh.tn.edu.tw'
      'tn.edu.tw'（等於 root）→ 略過
    """
    root = root.strip().lower().rstrip(".")
    n = len(root.split("."))

    second_levels = set()
    for d in full_domains:
        d = d.strip().lower().rstrip(".")
        if d == root:
            continue
        if not d.endswith("." + root):
            continue
        labels = d.split(".")
        if len(labels) <= n:
            continue
        second_label = labels[-(n + 1)]
        second_levels.add(f"{second_label}.{root}")

    return sorted(second_levels)


# ---- 主流程 ----
def main():
    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
        print("錯誤：請設定環境變數 SHODAN_API_KEY 或在 config.Config.SHODAN_API_KEY 設定金鑰。", file=sys.stderr)
        sys.exit(1)

    root_domain_to_search = input("請輸入要查詢的根網域 (例如: tn.edu.tw): ").strip().lower()
    if not root_domain_to_search:
        print("請輸入一個有效的網域。", file=sys.stderr)
        sys.exit(1)

    # 建立 log 檔名
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"shodan_{root_domain_to_search}_{ts}.log"
    logger = setup_logger(log_filename)

    # 開始查詢
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        logger.info(f"\n正在查詢 {root_domain_to_search} 的子網域（抓取所有分頁）...\n")
        merged_json = fetch_all_pages(api, root_domain_to_search, max_pages=None)

    except shodan.APIError as e:
        logger.info(f"Shodan API 錯誤：{e}")
        logger.info(f"\n已寫入 log 檔：{log_filename}")
        sys.exit(1)
    except Exception as e:
        logger.info(f"發生了一個錯誤：{e}")
        logger.info(f"\n已寫入 log 檔：{log_filename}")
        sys.exit(1)

    # 1) 原始 JSON（合併後）— 同時印到終端機 & 寫入 log
    logger.info("=== Shodan 原始 JSON（合併所有頁） ===")
    logger.info(json.dumps(merged_json, ensure_ascii=False, indent=2))

    # 2) 整理清單輸出
    all_subs = merged_json.get("subdomains", [])
    full_domains = [f"{sub}.{root_domain_to_search}" for sub in all_subs]
    full_domains.append(root_domain_to_search)

    count = len(full_domains)
    logger.info("\n=== 整理後的結果 ===")
    if count > 0:
        logger.info("--- 完整網域 ---")
        for domain_name in sorted(full_domains):
            logger.info(domain_name)
        logger.info(f"\n總共找到 {count} 個網域（包含根網域）。")

        second_level_domains = extract_second_level_under_root(root_domain_to_search, full_domains)
        logger.info("\n--- 次級網域（緊鄰 root 的一段 + root） ---")
        if second_level_domains:
            for sl_domain in second_level_domains:
                logger.info(sl_domain)
            logger.info(f"\n總共找到 {len(second_level_domains)} 個獨特的次級網域。")
        else:
            logger.info("沒有找到任何次級網域。")
    else:
        logger.info("找不到任何網域。")

    logger.info(f"\n已寫入 log 檔：{log_filename}")


if __name__ == "__main__":
    main()
