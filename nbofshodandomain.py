#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import shodan
import sys
import os  # NEW: 支援從環境變數讀取金鑰，較安全
from config import Config

# CHANGED: 不再需要 tldextract，因為台灣多層後綴（edu.tw）用字串切割更直覺
# import tldextract

# 你可以直接放金鑰，或改用環境變數 SHODAN_API_KEY
SHODAN_API_KEY = Config.SHODAN_API_KEY

def find_subdomains(domain: str):
    """
    使用 Shodan API 查詢指定網域的所有子網域。

    Args:
        domain (str): 要查詢的根網域 (例如: "tn.edu.tw")。

    Returns:
        tuple: (list of full domains, int total_count)
    """
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        domain_info = api.dns.domain_info(domain)
        subdomains = domain_info.get('subdomains', [])
        # 組合出完整的網域名稱
        full_domains = [f"{sub}.{domain}" for sub in subdomains]
        full_domains.append(domain)  # 包含根網域本身
        return full_domains, len(full_domains)

    except shodan.APIError as e:
        print(f"Shodan API 錯誤: {e}", file=sys.stderr)
        return [], 0
    except Exception as e:
        print(f"發生了一個錯誤: {e}", file=sys.stderr)
        return [], 0


# NEW: 以 root 為基準抽「次級網域」的函式
def extract_second_level_under_root(root: str, full_domains: list[str]) -> list[str]:
    """
    給定 root='tn.edu.tw' 與一堆完整網域（如 'doc.ptivs.tn.edu.tw'），
    回傳緊鄰 root 左側的一段 + root：
      - 'doc.ptivs.tn.edu.tw'  → 'ptivs.tn.edu.tw'
      - 'ad.tncvs.tn.edu.tw'   → 'tncvs.tn.edu.tw'
      - 'bookroom.tntcsh.tn.edu.tw' → 'tntcsh.tn.edu.tw'
      - 'tn.edu.tw'（等於 root）→ 略過
    """
    root = root.strip().lower().rstrip(".")
    root_labels = root.split(".")
    n = len(root_labels)

    second_levels = set()
    for d in full_domains:
        d = d.strip().lower().rstrip(".")
        if d == root:
            # 根網域本身不算次級
            continue

        # 必須是 *.root 才處理
        if not d.endswith("." + root):
            continue

        labels = d.split(".")
        if len(labels) <= n:
            # 長度不夠（理論上不會進來，保險用）
            continue

        # 取緊鄰 root 左邊那一段
        second_label = labels[-(n + 1)]
        second_levels.add(f"{second_label}.{root}")

    return sorted(second_levels)


def main():
    """主程式，處理使用者輸入與輸出。"""

    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
        print("錯誤: 請先將程式碼中的 'YOUR_SHODAN_API_KEY' 替換成你自己的金鑰，或設定環境變數 SHODAN_API_KEY。", file=sys.stderr)
        sys.exit(1)

    root_domain_to_search = input("請輸入要查詢的根網域 (例如: tn.edu.tw): ").strip().lower()

    if not root_domain_to_search:
        print("請輸入一個有效的網域。", file=sys.stderr)
        return

    print(f"\n正在查詢 {root_domain_to_search} 的子網域...\n")

    all_domains, count = find_subdomains(root_domain_to_search)

    if count > 0:
        print("--- 查詢結果（完整網域） ---")
        for domain_name in sorted(all_domains):
            print(domain_name)
        print(f"\n總共找到 {count} 個網域 (包含根網域)。")

        # CHANGED: 改為用字串切割法，準確抽「次級網域」
        second_level_domains = extract_second_level_under_root(root_domain_to_search, all_domains)  # NEW

        print("\n--- 次級網域統計（緊鄰 root 的一段 + root） ---")
        if second_level_domains:
            for sl_domain in second_level_domains:
                print(sl_domain)
            print(f"\n總共找到 {len(second_level_domains)} 個獨特的次級網域。")
        else:
            print("沒有找到任何次級網域。")

    else:
        print("找不到任何網域，或者發生了錯誤。")


if __name__ == "__main__":
    main()
