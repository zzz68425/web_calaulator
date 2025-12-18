"""
網站驗證器模組 (OTX API 版本)
"""
import threading
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import time
import dns.resolver
import dns.exception

from utils.logger import get_logger
from models.website import Website
from config import Config, _backoff_delay

# 可選：關掉 verify=False 的噪音警告
try:
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    pass

logger = get_logger("validators.otx_validator")

# 每個執行緒各自持有一個 Session（requests.Session 非 thread-safe）
_thread_local = threading.local()


class OtxValidator:
    """網站連線驗證器（使用 OTX API，支援多執行緒）"""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        if not self.config.OTX_API_KEY:
            raise ValueError("OTX_API_KEY 未在 config.py 中設定！")

    def _get_session(self) -> requests.Session:
        """在執行緒區域取得/建立 session"""
        sess = getattr(_thread_local, "session", None)
        if sess is not None:
            return sess

        sess = requests.Session()
        sess.headers.update({
            "User-Agent": self.config.USER_AGENT,
            "X-OTX-API-KEY": self.config.OTX_API_KEY
        })
        _thread_local.session = sess
        return sess

    # 不再進行 DNS 解析，僅檢查 OTX 是否存在相關 URL

    def _validate_single_host(self, fqdn: str) -> Optional[Website]:
        """
    透過 OTX API 驗證單一 FQDN：僅檢查是否存在關聯 URL。
    若 'url_list' 存在且非空，視為成功；不再從 OTX 抽取 IP，也不做 DNS 解析。
        """

        # 改用otx api取代requests進行網站驗證
        session = self._get_session()
        api_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{fqdn}/url_list"
        timeouts = (getattr(self.config, "CONNECT_TIMEOUT", 10.0),
                    getattr(self.config, "READ_TIMEOUT", 10.0))

        max_retries = getattr(self.config, 'OTX_MAX_RETRIES', 3)
        attempt = 0
        retry_delay = _backoff_delay(attempt)  # 使用指數退避 + full jitter

        while attempt <= max_retries:
            try:
                resp = session.get(api_url, timeout=timeouts)
                # 5xx 視為可重試
                if 500 <= resp.status_code < 600:
                    raise requests.exceptions.HTTPError(f"Server error {resp.status_code}", response=resp)
                resp.raise_for_status()
                data = resp.json()

                if not data.get("url_list"):
                    logger.debug(f"OTX 中未找到 {fqdn} 的關聯 URL。")
                    return None
                logger.debug(f"OTX 找到 {fqdn} 的關聯 URL，視為存在。")
                first_url = data["url_list"][0].get("url", f"http://{fqdn}")
                site = Website(
                    fqdn=fqdn,
                    url=first_url,
                    title=None,
                    status_code=None,
                    redirect_to=None
                )
                # 不設定 IP，讓 property 從 ipv4/ipv6 屬性動態取得
                return site

            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    logger.debug(f"OTX API 回應 404，找不到主機: {fqdn}")
                    return None
                attempt += 1
                if attempt > max_retries:
                    logger.error(f"OTX API 請求失敗（最終） {fqdn}: {e}")
                    return None
                logger.warning(f"OTX API 請求失敗 {fqdn} (attempt {attempt}/{max_retries})：{e}，{retry_delay}s 後重試")
                time.sleep(retry_delay)
                continue
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                attempt += 1
                if attempt > max_retries:
                    logger.error(f"OTX API 網路錯誤（最終） {fqdn}: {e}")
                    return None
                logger.warning(f"OTX API 網路錯誤 {fqdn} (attempt {attempt}/{max_retries})：{e}，{retry_delay}s 後重試")
                time.sleep(retry_delay)
                continue
            except Exception as e:
                logger.error(f"驗證 {fqdn} 時發生未預期例外：{e}")
                return None

        return None

    def validate_websites(self, subdomains: List[str], max_workers: Optional[int] = None) -> List[Website]:
        """
        批次驗證網站 (OTX 版本)
        - subdomains: 要測試的 FQDN 清單
        - max_workers: 併發數；預設取 config.VALIDATOR_MAX_WORKERS
        """
        subdomains = list(dict.fromkeys(s.strip() for s in subdomains if s.strip()))
        if not subdomains:
            return []

        workers = max_workers or getattr(self.config, "VALIDATOR_MAX_WORKERS", 16)
        logger.info(f"開始 OTX 多執行緒驗證，共 {len(subdomains)} 個目標，併發數={workers}")

        results: List[Website] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(self._validate_single_host, fqdn): fqdn for fqdn in subdomains}

            done_count = 0
            total_count = len(subdomains)
            for future in as_completed(future_map):
                try:
                    site = future.result()
                    if site:
                        results.append(site)
                except Exception as e:
                    fqdn = future_map[future]
                    logger.debug(f"驗證 {fqdn} 的 future 發生例外：{e}")
                finally:
                    done_count += 1
                    # 每 10% 或最後一筆時印出進度
                    if done_count % max(1, total_count // 10) == 0 or done_count == total_count:
                        logger.info(f"進度：{done_count}/{total_count} 完成")

        logger.info(f"OTX 多執行緒驗證完成，成功 {len(results)}/{total_count}")
        return results

    def fetch_http_scans(self, fqdn: str) -> List[dict]:
        """
        取得單一 FQDN 的 OTX HTTP Scans 資料
        
        Args:
            fqdn: 要查詢的完整域名
            
        Returns:
            包含 http_scans 資料的 list，每筆包含 key, name, value
            若查詢失敗或無資料則返回空 list
        """
        session = self._get_session()
        api_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{fqdn}/http_scans"
        timeouts = (getattr(self.config, "CONNECT_TIMEOUT", 10.0),
                    getattr(self.config, "READ_TIMEOUT", 10.0))

        max_retries = getattr(self.config, 'OTX_MAX_RETRIES', 3)
        attempt = 0
        retry_delay = _backoff_delay(attempt)

        while attempt <= max_retries:
            try:
                resp = session.get(api_url, timeout=timeouts)
                # 5xx 視為可重試
                if 500 <= resp.status_code < 600:
                    raise requests.exceptions.HTTPError(f"Server error {resp.status_code}", response=resp)
                resp.raise_for_status()
                data = resp.json()

                http_scans = data.get("data", [])
                if http_scans:
                    logger.debug(f"OTX 取得 {fqdn} 的 {len(http_scans)} 筆 http_scans 資料")
                else:
                    logger.debug(f"OTX 中未找到 {fqdn} 的 http_scans 資料")
                return http_scans

            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    logger.debug(f"OTX http_scans API 回應 404，找不到主機: {fqdn}")
                    return []
                attempt += 1
                if attempt > max_retries:
                    logger.error(f"OTX http_scans API 請求失敗（最終） {fqdn}: {e}")
                    return []
                logger.warning(f"OTX http_scans API 請求失敗 {fqdn} (attempt {attempt}/{max_retries})：{e}，{retry_delay}s 後重試")
                time.sleep(retry_delay)
                continue
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                attempt += 1
                if attempt > max_retries:
                    logger.error(f"OTX http_scans API 網路錯誤（最終） {fqdn}: {e}")
                    return []
                logger.warning(f"OTX http_scans API 網路錯誤 {fqdn} (attempt {attempt}/{max_retries})：{e}，{retry_delay}s 後重試")
                time.sleep(retry_delay)
                continue
            except Exception as e:
                logger.error(f"取得 {fqdn} http_scans 時發生未預期例外：{e}")
                return []

        return []

    def fetch_http_scans_batch(self, fqdns: List[str], max_workers: Optional[int] = None) -> dict[str, List[dict]]:
        """
        批次取得多個 FQDN 的 OTX HTTP Scans 資料
        
        Args:
            fqdns: 要查詢的 FQDN 清單
            max_workers: 併發數；預設取 config.VALIDATOR_MAX_WORKERS
            
        Returns:
            {fqdn: [http_scans_data]} 的字典
        """
        fqdns = list(dict.fromkeys(s.strip() for s in fqdns if s.strip()))
        if not fqdns:
            return {}

        workers = max_workers or getattr(self.config, "VALIDATOR_MAX_WORKERS", 16)
        logger.info(f"開始批次取得 OTX http_scans，共 {len(fqdns)} 個目標，併發數={workers}")

        results: dict[str, List[dict]] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(self.fetch_http_scans, fqdn): fqdn for fqdn in fqdns}

            done_count = 0
            total_count = len(fqdns)
            for future in as_completed(future_map):
                fqdn = future_map[future]
                try:
                    scans = future.result()
                    if scans:
                        results[fqdn] = scans
                except Exception as e:
                    logger.debug(f"取得 {fqdn} http_scans 的 future 發生例外：{e}")
                finally:
                    done_count += 1
                    if done_count % max(1, total_count // 10) == 0 or done_count == total_count:
                        logger.info(f"http_scans 進度：{done_count}/{total_count} 完成")

        logger.info(f"OTX http_scans 批次取得完成，成功 {len(results)}/{total_count}")
        return results