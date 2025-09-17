"""
網站驗證器模組 (OTX API 版本)
"""
import socket
import threading
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from utils.logger import get_logger
from models.website import Website
from config import Config

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

    def _resolve_domain(self, domain: str) -> Optional[str]:
        """解析 A 紀錄，失敗則回傳 None"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            logger.debug(f"DNS 解析失敗: {domain}")
            return None

    def _validate_single_host(self, fqdn: str) -> Optional[Website]:
        """
        透過 OTX API 驗證單一 FQDN。
        如果 'url_list' 存在且非空，則視為成功。
        IP 位址將直接從 API 回應的 'urlworker' 欄位取得。
        """
        session = self._get_session()
        api_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{fqdn}/url_list"
        timeouts = (getattr(self.config, "CONNECT_TIMEOUT", 5.0),
                    getattr(self.config, "READ_TIMEOUT", 10.0))

        try:
            resp = session.get(api_url, timeout=timeouts)
            resp.raise_for_status()
            data = resp.json()

            # 核心邏輯：檢查 url_list 是否存在且有內容
            if data.get("url_list"):
                logger.debug(f"OTX 找到 {fqdn} 的關聯 URL。")
                
                # 從 API 回應中直接取得 IP 位址
                try:
                    ip_address = data["url_list"][0]["result"]["urlworker"]["ip"]
                except (KeyError, IndexError, TypeError):
                    logger.warning(f"OTX 驗證成功，但無法從 API 回應中找到 {fqdn} 的 IP 位址，將略過此筆資料。")
                    return None

                # 建立 Website 物件
                first_url = data["url_list"][0].get("url", f"http://{fqdn}")
                site = Website(
                    fqdn=fqdn,
                    ip=ip_address,
                    url=first_url,
                    # OTX API 不直接提供這些資訊，設為 None
                    title=None,
                    status_code=None,
                    redirect_to=None
                )
                return site
            else:
                logger.debug(f"OTX 中未找到 {fqdn} 的關聯 URL。")
                return None

        except requests.exceptions.HTTPError as e:
            # 404 Not Found 是正常情況，代表 OTX 沒有該主機資料
            if e.response.status_code == 404:
                logger.debug(f"OTX API 回應 404，找不到主機: {fqdn}")
            else:
                logger.error(f"OTX API 請求失敗 ({fqdn})，狀態碼: {e.response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"OTX API 請求發生網路錯誤 ({fqdn}): {e}")
        except Exception as e:
            logger.error(f"驗證 {fqdn} 時發生未預期例外：{e}")

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