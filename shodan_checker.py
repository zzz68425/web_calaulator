# -*- coding: utf-8 -*-

"""
Shodan 憑證查詢測試工具
- 以憑證 CN pattern 查詢 Shodan（可選 country/port）
- 印出 Shodan 回傳完整 JSON
- 解析並列出 IP 與 .edu.tw 域名
"""
import sys 
import os
import re
import json
import time
from typing import Dict, List, Set, Any, Iterable
from dotenv import load_dotenv

# 嘗試載入環境變數
load_dotenv()

# -----------------------------
# 資料結構
# -----------------------------
class ShodanResult:
    def __init__(self):
        self.total_results: int = 0
        self.domains: List[str] = []
        self.ips: List[str] = []

# -----------------------------
# 解析工具
# -----------------------------
def _clean_domain(domain: str) -> str:
    if not isinstance(domain, str):
        return ""
    d = domain.strip()
    if d.startswith("DNS:"):
        d = d[4:]
    if d.startswith("*."):
        d = d[2:]
    return d.lower()

def _is_valid_domain(domain: str) -> bool:
    if not domain or not isinstance(domain, str):
        return False
    d = domain.strip().lower()
    if not d.endswith(".edu.tw"):
        return False
    if len(d) < 8:  # 最短像 x.edu.tw
        return False
    return re.match(r"^[a-z0-9.-]+$", d) is not None

def parse_results(raw_results: Dict[str, Any]) -> ShodanResult:
    result = ShodanResult()
    result.total_results = raw_results.get("total", 0)

    ips: Set[str] = set()
    domains: Set[str] = set()

    print("=== Shodan Raw JSON ===")
    # 這裡只列出前 5 個 matches，避免輸出過長
    raw_copy = raw_results.copy()
    raw_copy['matches'] = raw_copy['matches'][:100]
    print(json.dumps(raw_copy, indent=2, ensure_ascii=False))
    
    print(f"\n找到 {result.total_results} 筆 Shodan 結果")
    for match in raw_results.get("matches", []):
        # 收集 IP
        ip = match.get("ip_str")
        if ip:
            ips.add(ip)

        # 收集 domains
        for d in match.get("domains", []) or []:
            dom = _clean_domain(d)
            if _is_valid_domain(dom):
                domains.add(dom)
    
    result.ips = sorted(list(ips))
    result.domains = sorted(list(domains))

    print("\n=== 解析後結果 ===")
    print(f"IP（{len(result.ips)}）:", result.ips)
    print(f"Domains（{len(result.domains)}）:", result.domains)
    return result

# -----------------------------
# Shodan 查詢
# -----------------------------
def run_shodan_full_query(api_key: str, cert_pattern: str, country: str, port: str) -> Dict[str, Any]:
    """
    呼叫 Shodan 搜尋，自動處理分頁以獲取所有結果。
    """
    try:
        import shodan
    except ImportError:
        raise RuntimeError("找不到 shodan 套件。請先執行：pip install shodan")

    api = shodan.Shodan(api_key)
    query = f'port:"{port}" country:"{country}" ssl.cert.subject.cn:"{cert_pattern}"'
    
    print(f"查詢語法：{query}")
    print("正在獲取所有結果，這可能需要一些時間並消耗多個查詢點數...")

    all_matches = []
    page = 1
    total = 0
    while True:
        try:
            results = api.search(query, page=page)
            if not total:
                total = results.get('total', 0)
                print(f"總計 {total} 筆結果。")

            current_matches = results.get('matches', [])
            if not current_matches:
                print(f"第 {page} 頁沒有更多結果，查詢結束。")
                break
            
            all_matches.extend(current_matches)
            
            print(f"已獲取 {len(all_matches)} / {total} 筆結果 (第 {page} 頁)。")

            if len(all_matches) >= total:
                print("所有結果已獲取。")
                break
            
            page += 1
            time.sleep(1) # 暫停一下，避免發出太多請求
            
        except shodan.APIError as e:
            print(f"Shodan API 錯誤: {e}", file=sys.stderr)
            break
        except Exception as e:
            print(f"發生了一個錯誤: {e}", file=sys.stderr)
            break
    
    return {
        'total': total,
        'matches': all_matches,
    }

# -----------------------------
# CLI
# -----------------------------
def main():
    print("=== Shodan 憑證查詢工具 (全量查詢模式) ===")

    # 取得 API Key
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        api_key = input("請輸入 Shodan API Key: ").strip()
    if not api_key:
        print("錯誤: 缺少 API Key，程式終止。", file=sys.stderr)
        return

    # 取得憑證 CN
    cert_cn = input("請輸入憑證 CN pattern (例如: *.tnu.edu.tw): ").strip()
    if not cert_cn:
        print("錯誤: 缺少憑證 CN pattern，程式終止。", file=sys.stderr)
        return

    # 取得可選參數
    country = input("請輸入國家代碼 (預設 TW): ").strip() or "TW"
    port = input("請輸入連接埠 (預設 443): ").strip() or "443"
    
    # 執行查詢
    try:
        raw_results = run_shodan_full_query(api_key=api_key, cert_pattern=cert_cn, country=country, port=port)
        parse_results(raw_results)
    except Exception as e:
        print(f"\n錯誤: 查詢失敗 - {e}", file=sys.stderr)

if __name__ == "__main__":
    main()