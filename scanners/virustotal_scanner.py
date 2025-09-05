"""
VirusTotal 掃描器模組（使用 API v3，分頁取得完整子域名）
"""
import time
import requests
from typing import List
import logging
from urllib.parse import urlparse, parse_qs
from scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class VirusTotalScanner(BaseScanner):
    """VirusTotal 掃描器（v3）"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.headers = {"x-apikey": api_key}

    def scan(self, domain: str) -> List[str]:
        """查詢域名的子域名（v3）"""
        return self.get_subdomains(domain)

    def get_subdomains(self, domain: str) -> List[str]:
        """獲取完整子域名列表（自動分頁）"""
        logger.info(f"查詢 VirusTotal(v3) 子域名: {domain}")

        url = f"{self.BASE_URL}/domains/{domain}/subdomains"
        all_subdomains: List[str] = []
        cursor = None
        page = 1

        while True:
            params = {"limit": 40}
            if cursor:
                params["cursor"] = cursor

            try:
                resp = requests.get(url, headers=self.headers, params=params, timeout=30)

                if resp.status_code == 200:
                    data = resp.json()

                    page_subdomains: List[str] = []
                    for item in data.get("data", []):
                        sub_id = item.get("id", "").strip()
                        if sub_id and sub_id not in all_subdomains:
                            all_subdomains.append(sub_id)
                            page_subdomains.append(sub_id)

                    logger.info(f"VT v3 子域名 - 第 {page} 頁獲取 {len(page_subdomains)} 個，累計 {len(all_subdomains)} 個")

                    next_link = data.get("links", {}).get("next")
                    if not next_link:
                        break

                    parsed = urlparse(next_link)
                    new_cursor = parse_qs(parsed.query).get("cursor", [None])[0]
                    if not new_cursor or new_cursor == cursor:
                        break

                    cursor = new_cursor
                    page += 1
                    # 公開 API 速率限制嚴格（約 4 req/min），保守等待
                    time.sleep(15)

                elif resp.status_code == 429:
                    logger.warning("VirusTotal API 速率限制，等待 60 秒後重試")
                    time.sleep(60)
                    continue
                elif resp.status_code == 404:
                    logger.warning("域名未找到或沒有子域名")
                    break
                elif resp.status_code == 401:
                    logger.error("VirusTotal API Key 無效")
                    break
                else:
                    logger.error(f"VirusTotal 回應錯誤: {resp.status_code}")
                    break

            except Exception as e:
                logger.error(f"查詢失敗: {e}")
                break

        logger.info(f"VT v3 子域名 - 總計 {len(all_subdomains)} 個")
        return sorted(all_subdomains)

    def parse_results(self, raw_results: dict) -> List[str]:
        """為符合抽象介面而提供的解析器（v3: 解析 data[].id）。"""
        try:
            subdomains: List[str] = []
            for item in raw_results.get("data", []):
                sub_id = (item or {}).get("id", "").strip()
                if sub_id:
                    subdomains.append(sub_id)
            return subdomains
        except Exception:
            return []