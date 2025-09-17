"""
網站驗證器模組（多執行緒版）
"""
import re
import socket
import threading
import requests
import dns.resolver
from typing import Optional, List
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import get_logger
from models.website import Website
from config import Config

# 可選：關掉 verify=False 的噪音警告
try:
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    pass

logger = get_logger("validators.website_validator")

# 每個執行緒各自持有一個 Session（requests.Session 非 thread-safe）
_thread_local = threading.local()


class WebsiteValidator:
    """網站連線驗證器（支援多執行緒）"""

    def __init__(self, config: Config = None):
        self.config = config or Config()

    # ---------- Session 與連線池/重試設定 ----------
    def _get_session(self) -> requests.Session:
        """在執行緒區域取得/建立 session（含連線池與重試）"""
        sess = getattr(_thread_local, "session", None)
        if sess is not None:
            return sess

        sess = requests.Session()
        sess.headers.update({"User-Agent": self.config.USER_AGENT})

        # 連線池 + 重試
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util import Retry
            retries = Retry(
                total=self.config.HTTP_RETRIES,
                backoff_factor=0.4,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD"])
            )
            adapter = HTTPAdapter(
                pool_connections=self.config.HTTP_POOL_SIZE,
                pool_maxsize=self.config.HTTP_POOL_SIZE,
                max_retries=retries
            )
            # 用於將 adapter 綁定在 HTTP 與 HTTPS
            sess.mount("http://", adapter)
            sess.mount("https://", adapter)
        except Exception:
            # 若環境沒有 urllib3.Retry 也不致於壞掉
            pass

        _thread_local.session = sess
        return sess

    # ---------- 對外 API ----------
    def validate_websites(self, subdomains: List[str], max_workers: Optional[int] = None) -> List[Website]:
        """
        批次驗證網站連線性（多執行緒）
        - subdomains: 要測試的 FQDN 清單
        - max_workers: 併發數；預設取 config.VALIDATOR_MAX_WORKERS
        """
        subdomains = list(dict.fromkeys(s.strip() for s in subdomains if s.strip()))  # 去重/清理
        if not subdomains:
            return []

        workers = max_workers or getattr(self.config, "VALIDATOR_MAX_WORKERS", 16)
        #logger.info(f"開始多執行緒驗證，共 {len(subdomains)} 個目標，併發數={workers}")

        results: List[Website] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(self._validate_single_host, fqdn): fqdn for fqdn in subdomains}

            done_count = 0
            for future in as_completed(future_map):
                fqdn = future_map[future]
                try:
                    site = future.result()
                    if site:
                        results.append(site)
                except Exception as e:
                    logger.debug(f"驗證 {fqdn} 時發生例外：{e}")
                finally:
                    done_count += 1
                    if done_count % max(1, len(subdomains)//10) == 0 or done_count == len(subdomains):
                        logger.info(f"進度：{done_count}/{len(subdomains)} 完成")

        logger.info(f"多執行緒驗證完成，成功 {len(results)}/{len(subdomains)}")
        return results

    # ---------- 單一任務 ----------
    def _validate_single_host(self, subdomain: str) -> Optional[Website]:
        """
        驗證單一 FQDN：先試 HTTPS，再試 HTTP。
        成功（2xx）或可接受的 3xx redirect 視為成功，回傳 Website。
        """
        session = self._get_session()
        timeouts = (getattr(self.config, "CONNECT_TIMEOUT", 5.0),
                    getattr(self.config, "READ_TIMEOUT", 7.0))

        for protocol in ("https", "http"):
            url = f"{protocol}://{subdomain}"
            try:
                resp = session.get(
                    url,
                    timeout=timeouts,
                    verify=False,
                    allow_redirects=True,
                )
                status = resp.status_code

                if status in (200, 301, 302, 303, 307, 308):
                    ip_address = self.resolve_domain(subdomain)
                    if not ip_address:
                        logger.debug(f"無法解析 IP: {subdomain}")
                        continue

                    title = self.extract_title(resp.text) if status == 200 else None

                    site = Website(
                        fqdn=subdomain,
                        ip=ip_address,
                        url=url,
                        protocol=protocol,
                        status_code=status,
                        redirect_to=resp.headers.get("Location") if 300 <= status < 400 else None,
                        title=title,
                    )
                    logger.info(f"{subdomain} ({protocol.upper()}) - 狀態碼: {status}")
                    return site

            except requests.exceptions.SSLError:
                logger.debug(f"{protocol.upper()} SSL 錯誤: {subdomain}")
            except requests.exceptions.Timeout:
                logger.debug(f"{protocol.upper()} 逾時: {subdomain}")
            except requests.exceptions.ConnectionError:
                logger.debug(f"{protocol.upper()} 連線失敗: {subdomain}")
            except Exception as e:
                logger.debug(f"{protocol.upper()} 錯誤: {subdomain} - {str(e)[:80]}")

        logger.debug(f"{subdomain} - 無法連線")
        return None

    # ---------- DNS 與 HTML 工具 ----------
    def resolve_domain(self, domain: str) -> Optional[str]:
        """
        解析 A 紀錄；使用新的 resolver 實例避免共享狀態。
        失敗則退回 socket.gethostbyname。
        """
        try:
            res = dns.resolver.Resolver()
            res.lifetime = getattr(self.config, "CONNECT_TIMEOUT", 5.0)
            answers = res.resolve(domain, "A")
            return str(answers[0])
        except Exception:
            try:
                return socket.gethostbyname(domain)
            except Exception:
                return None

    def extract_title(self, html_content: str) -> Optional[str]:
        """提取 <title> 文字"""
        try:
            m = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
            if m:
                title = re.sub(r"\s+", " ", m.group(1).strip())
                return title[:100]
        except Exception:
            pass
        return None