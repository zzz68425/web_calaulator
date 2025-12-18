"""
VirusTotal 掃描器模組（使用 API v3，分頁取得完整子域名）
"""
import time
import requests
from typing import List, Optional, Sequence
from utils.logger import get_logger
from urllib.parse import urlparse, parse_qs
from scanners.base import BaseScanner

logger = get_logger("scanners.virustotal_scanner")


class VirusTotalScanner(BaseScanner):
    """VirusTotal 掃描器（v3）

    功能新增：支援多組 API Key 輪替。
    當收到 429 (Rate Limit) 時，嘗試切換下一組 key 再重試；
    若所有 key 都在同一輪中用過仍 429，才進入較長等待再重新開始新一輪。
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | Sequence[str]):
        """
        api_key 可以是：
        - 單一字串 API key
        - 多個 key 以逗號分隔的字串 (e.g. "key1,key2,key3")
        - 直接傳入 list/tuple[str]
        """
        if isinstance(api_key, (list, tuple)):
            keys = [k.strip() for k in api_key if k and isinstance(k, str)]
        else:
            # 若包含逗號表示多 key
            parts = [p.strip() for p in str(api_key).split(",")]
            keys = [p for p in parts if p]

        if not keys:
            raise ValueError("必須提供至少一組 VirusTotal API Key")

        # 去重並保持順序
        seen = set()
        ordered_keys: List[str] = []
        for k in keys:
            if k not in seen:
                seen.add(k)
                ordered_keys.append(k)

        self.api_keys: List[str] = ordered_keys
        self._key_index: int = 0
        super().__init__(self.api_keys[0])  # 保留父類別紀錄第一組
        self.headers = {"x-apikey": self.api_keys[0]}

        # 參數：可調整
        self.rotate_wait_seconds = 2          # 切換 key 前的小等待（避免過快）
        self.full_cycle_cooldown = 60         # 所有 key 都 hit 429 後的冷卻等待秒數
        self.per_page_sleep = 15              # 正常翻頁間隔（符合公開 API 限制）

        logger.info(f"[VT] 啟用 {len(self.api_keys)} 組 API Key 輪替機制")

    # -------------------------------------------------
    def _set_key(self, idx: int):
        self._key_index = idx % len(self.api_keys)
        self.headers = {"x-apikey": self.api_keys[self._key_index]}
        logger.info(f"[VT] 切換使用第 {self._key_index + 1}/{len(self.api_keys)} 組 API Key")

    def _next_key(self) -> bool:
        """切換到下一組 key；若已經回到起始代表一輪結束，回傳 False。"""
        current = self._key_index
        new_index = (current + 1) % len(self.api_keys)
        if new_index == 0:  # 代表一輪結束
            return False
        self._set_key(new_index)
        return True

    # -------------------------------------------------
    def scan(self, domain: str) -> List[str]:
        """查詢域名的子域名（v3）"""
        logger.info(f"[VT] 開始分析：{domain}")
        return self.get_subdomains(domain)

    def get_subdomains(self, domain: str) -> List[str]:
        """獲取完整子域名列表（自動分頁 + 多 key 輪替）"""
        logger.info(f"[VT] 查詢子域名（v3）：{domain}")

        url = f"{self.BASE_URL}/domains/{domain}/subdomains"
        all_subdomains: List[str] = []
        cursor: Optional[str] = None
        page = 1

        # 紀錄本輪是否所有 key 都遭遇 429
        keys_429_in_this_cycle = set()

        while True:
            params = {"limit": 40}
            if cursor:
                params["cursor"] = cursor

            try:
                resp = requests.get(url, headers=self.headers, params=params, timeout=30)

                if resp.status_code == 200:
                    keys_429_in_this_cycle.clear()  # 成功即重置429循環追蹤
                    data = resp.json()

                    page_subdomains: List[str] = []
                    for item in data.get("data", []):
                        sub_id = item.get("id", "").strip()
                        if sub_id and sub_id not in all_subdomains:
                            all_subdomains.append(sub_id)
                            page_subdomains.append(sub_id)

                    logger.info(
                        f"[VT] {domain} - 第 {page} 頁取得 {len(page_subdomains)} 個，累計 {len(all_subdomains)} 個"
                    )

                    next_link = data.get("links", {}).get("next")
                    if not next_link:
                        logger.info(f"[VT] {domain} - 沒有下一頁，結束。")
                        break

                    parsed = urlparse(next_link)
                    new_cursor = parse_qs(parsed.query).get("cursor", [None])[0]
                    if not new_cursor or new_cursor == cursor:
                        logger.info(f"[VT] {domain} - 游標重複/無效，結束。")
                        break

                    cursor = new_cursor
                    page += 1
                    time.sleep(self.per_page_sleep)

                elif resp.status_code == 429:
                    logger.warning(f"[VT] {domain} - 速率限制（429），嘗試切換 API Key")
                    keys_429_in_this_cycle.add(self._key_index)

                    # 嘗試切換下一組 key
                    if self._next_key():
                        time.sleep(self.rotate_wait_seconds)
                        continue  # 重新發送同一頁
                    else:
                        # _next_key() 回傳 False 表示換到下一把會回到 index 0（wrap-around）
                        # 這不一定代表「一輪已經用盡」，因為本輪可能尚未嘗試所有 key（例如起始點剛好在最後一把）。
                        if len(keys_429_in_this_cycle) < len(self.api_keys):
                            # 尚未嘗試到所有 key：明確切到第一把（index 0），繼續重試同一頁
                            logger.info(f"[VT] {domain} - 429 wrap 到起點，尚有未嘗試的 key，切回第 1 把繼續")
                            self._set_key(0)
                            time.sleep(self.rotate_wait_seconds)
                            continue
                        else:
                            # 一輪中的每把 key 都遭遇 429：進入冷卻
                            logger.warning(
                                f"[VT] {domain} - 所有 {len(self.api_keys)} 組 key 都遭遇 429，等待 {self.full_cycle_cooldown}s 再重試"
                            )
                            time.sleep(self.full_cycle_cooldown)
                            keys_429_in_this_cycle.clear()
                            continue

                elif resp.status_code == 404:
                    logger.warning(f"[VT] {domain} - 未找到或沒有子域名（404）")
                    break
                elif resp.status_code == 401:
                    logger.error(f"[VT] {domain} - API Key 無效（401）")
                    break
                else:
                    logger.error(f"[VT] {domain} - 回應錯誤: {resp.status_code}")
                    break

            except Exception as e:
                logger.error(f"[VT] {domain} - 查詢失敗：{e}")
                break

        logger.info(f"[VT] {domain} - 子域名總計 {len(all_subdomains)} 個")
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
