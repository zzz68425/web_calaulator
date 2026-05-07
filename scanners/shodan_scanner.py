"""
Shodan 掃描器模組（全量分頁抓取）
- 逐頁呼叫 api.search(query, page=N) 直到拿滿 total 或達到最大頁數
- 依序從 domains > hostnames > ssl.cert 解析 .edu.tw 網域
- 產出 vt_query_targets（配合你現有的 area 邏輯）
"""
import time
import shodan
from typing import List, Set, Optional, Dict, Any
from scanners.base import BaseScanner
from models.website import ShodanResult
from utils.logger import get_logger
from database.repository import DatabaseManagerORM

logger = get_logger("scanners.shodan_scanner")


def _norm_host(value: Optional[str]) -> str:
    """Normalize hostname for exact comparisons."""
    return (value or "").strip().lower().rstrip(".")


def _match_belongs_to_target(match: dict, target_fqdn: str) -> bool:
    """Return True only when a Shodan match can be attributed to target fqdn."""
    target = _norm_host(target_fqdn)
    if not target:
        return False

    # 1) Most reliable: crawler's original hostname target
    shodan_opts = (match.get("_shodan") or {}).get("options") or {}
    if _norm_host(shodan_opts.get("hostname")) == target:
        return True

    # 2) HTTP host field
    http_host = _norm_host((match.get("http") or {}).get("host"))
    if http_host == target:
        return True

    # 3) Hostnames/domain list exact match
    for h in match.get("hostnames", []) or []:
        if _norm_host(h) == target:
            return True
    for d in match.get("domains", []) or []:
        if _norm_host(d) == target:
            return True

    return False


class ShodanScanner(BaseScanner):
    """Shodan 掃描器（支援全量分頁抓取）"""

    def __init__(
        self,
        api_key: str,
        db_manager: Optional[DatabaseManagerORM] = None,
        page_delay: float = 1.0,            # 每頁間的延遲（秒），避免過度頻繁請求
        max_pages: Optional[int] = None,    # 安全上限；None 表示不限制，按 total 跑完
        empty_page_retries: int = 2,        # 新增：當某頁 matches 為空時的重試次數
        retry_delay: float = 15,           # 新增：重試前延遲秒數
    ):
        super().__init__(api_key)
        self.api = shodan.Shodan(api_key)
        self.db_manager = db_manager
        self.page_delay = page_delay
        self.max_pages = max_pages
        self.empty_page_retries = max(0, int(empty_page_retries))
        self.retry_delay = max(0.0, float(retry_delay))

    # -------------------- 對外 API --------------------
    def scan(self, cert_pattern: str, country: str = "TW", port: str = "443") -> ShodanResult:
        """搜尋特定憑證模式（全量分頁）"""
        query = f'port:"{port}" country:"{country}" ssl.cert.subject.cn:"{cert_pattern}"'
        logger.info(f"Shodan 查詢: {query}")

        try:
            raw_all = self._search_all_pages(query)
            return self.parse_results(raw_all)
        except shodan.APIError as e:
            logger.error(f"Shodan API 錯誤: {e}")
            return ShodanResult()
        except Exception as e:
            logger.error(f"搜尋失敗: {e}")
            return ShodanResult()

    # -------------------- 內部：分頁抓取 --------------------
    def _search_all_pages(self, query: str) -> Dict[str, Any]:
        """
        逐頁呼叫 Shodan 搜尋，合併所有 matches。
        回傳結構：{'total': int, 'matches': list}
        """
        page = 1
        total: int = 0
        all_matches: List[Dict[str, Any]] = []

        while True:
            if self.max_pages is not None and page > self.max_pages:
                logger.info(f"已達最大頁數上限 max_pages={self.max_pages}，停止抓取。")
                break

            results = self.api.search(query, page=page)

            if page == 1:
                total = int(results.get("total", 0))
                logger.info(f"Shodan 回報總筆數：{total}")

            matches = results.get("matches", [])
            if not matches:
                # 空頁重試機制
                attempted = 0
                while attempted < self.empty_page_retries:
                    attempted += 1
                    logger.info(f"第 {page} 頁為空，準備重試 {attempted}/{self.empty_page_retries}，等待 {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                    try:
                        retry_results = self.api.search(query, page=page)
                        retry_matches = retry_results.get("matches", [])
                        if retry_matches:
                            matches = retry_matches
                            logger.info(f"重試成功：第 {page} 頁取得 {len(matches)} 筆。")
                            break
                    except shodan.APIError as e:
                        logger.warning(f"重試時遇到 Shodan API 錯誤（第 {page} 頁）：{e}")
                        break
                    except Exception as e:
                        logger.warning(f"重試時遇到例外（第 {page} 頁）：{e}")
                        # 繼續下一次重試
                        continue

                if not matches:
                    logger.info(f"第 {page} 頁無更多資料，停止。")
                    break

            all_matches.extend(matches)
            logger.info(f"已取回 {len(all_matches)}/{total} 筆（第 {page} 頁，{len(matches)} 筆）。")

            # 拿滿了就停
            if len(all_matches) >= total:
                logger.info("已取得所有結果。")
                break

            page += 1
            time.sleep(self.page_delay)  # 友善一點，避免太快

        return {"total": total, "matches": all_matches}

    # -------------------- 解析邏輯 --------------------
    def parse_results(self, raw_results: dict) -> ShodanResult:
        """解析 Shodan 結果：從 domains/hostnames/ssl.cert 擷取 .edu.tw 網域；準備 VT 目標。"""
        result = ShodanResult()
        result.total_results = raw_results.get("total", 0)

        domains: Set[str] = set()
        ips: Set[str] = set()
        vt_targets: Set[str] = set()

        logger.info(f"開始解析 {len(raw_results.get('matches', []))} 筆 matches（total={result.total_results}）。")

        for match in raw_results.get("matches", []) or []:
            # 收集 IP
            ip = match.get("ip_str")
            if ip:
                ips.add(ip)

            collected_this_match: Set[str] = set()

            # 1) domains 欄位（優先）
            for d in match.get("domains", []) or []:
                if isinstance(d, str):
                    clean_d = self._clean_domain(d)
                    if self._is_valid_domain(clean_d):
                        collected_this_match.add(clean_d)
                        logger.debug(f"domains: {clean_d}")

            # 2) hostnames 欄位（補充）
            if not collected_this_match:
                for h in match.get("hostnames", []) or []:
                    if isinstance(h, str):
                        clean_h = self._clean_domain(h)
                        if self._is_valid_domain(clean_h):
                            collected_this_match.add(clean_h)
                            logger.debug(f"hostnames: {clean_h}")

            # 3) ssl.cert（再補）
            if not collected_this_match:
                ssl_info = match.get("ssl", {}) or {}
                cert = ssl_info.get("cert")
                if isinstance(cert, dict):
                    for cd in self._extract_domains_from_cert(cert):
                        if self._is_valid_domain(cd):
                            collected_this_match.add(cd)
                            logger.debug(f"ssl.cert: {cd}")

            # 合併總集合
            domains.update(collected_this_match)

            # area 比對（決定 VT 查詢目標）
            for clean_d in collected_this_match:
                if self.db_manager and self.db_manager.find_area_domain(clean_d):
                    hostnames = match.get("hostnames", []) or []
                    hostname_target = self._extract_subdomain_from_hostname(hostnames, clean_d)
                    if hostname_target:
                        vt_targets.add(hostname_target)
                        logger.info(f"area 命中 {clean_d} → hostname 提取: {hostname_target}")
                    else:
                        vt_targets.add(clean_d)
                        logger.info(f"area 命中但無法提取 hostname，改用: {clean_d}")
                else:
                    vt_targets.add(clean_d)

        result.domains = sorted(domains)
        result.ips = sorted(ips)
        # 若你的 ShodanResult 沒這欄，請參考下方「模型擴充」
        result.vt_query_targets = sorted(vt_targets)

        logger.info(f"解析完成：{len(result.domains)} 個域名、{len(result.ips)} 個 IP、{len(result.vt_query_targets)} 個 VT 目標。")
        return result

    # -------------------- 小工具 --------------------
    def _extract_subdomain_from_hostname(self, hostnames: List[str], area_domain: str) -> Optional[str]:
        area_labels = area_domain.split(".")
        for hostname in hostnames:
            if not isinstance(hostname, str):
                continue
            h = hostname.strip().lower()
            if not h or "." not in h:
                continue
            h_labels = h.split(".")
            if len(h_labels) <= len(area_labels):
                continue
            if h_labels[-len(area_labels):] != area_labels:
                continue
            prefix_labels = h_labels[: -len(area_labels)]
            if not prefix_labels:
                continue
            last_prefix = prefix_labels[-1]
            return f"{last_prefix}.{area_domain}"
        return None

    def _extract_domains_from_cert(self, cert: dict) -> Set[str]:
        domains: Set[str] = set()
        subject = cert.get("subject", [])
        if isinstance(subject, list):
            for item in subject:
                if isinstance(item, list) and len(item) >= 2 and item[0] == "CN":
                    cn = self._clean_domain(item[1])
                    if cn:
                        domains.add(cn)
        extensions = cert.get("extensions")
        if isinstance(extensions, list):
            for ext in extensions:
                if isinstance(ext, dict) and ext.get("name") == "subjectAltName":
                    san_data = ext.get("data", "")
                    if isinstance(san_data, string_types := str):
                        for token in san_data.split(","):
                            token = token.strip()
                            if token.startswith("DNS:"):
                                san = self._clean_domain(token[4:])
                                if san:
                                    domains.add(san)
        elif isinstance(extensions, dict):
            san_list = extensions.get("subjectAltName", [])
            if isinstance(san_list, list):
                for san in san_list:
                    if isinstance(san, str):
                        domains.add(self._clean_domain(san))
        return {d for d in domains if d}

    def _clean_domain(self, domain: str) -> str:
        if not isinstance(domain, str):
            return ""
        d = domain.strip()
        if d.startswith("*."):
            d = d[2:]
        if d.startswith("DNS:"):
            d = d[4:]
        return d.lower()

    def _is_valid_domain(self, domain: str) -> bool:
        if not domain:
            return False
        if not domain.endswith(".edu.tw"):
            return False
        if len(domain) < 8:
            return False
        import re as _re
        return bool(_re.match(r"^[a-z0-9.-]+$", domain))


# ==================== Shodan HTTP 查詢函式 ====================

def fetch_shodan_http_batch(api_key: str, subdomains: List[str], delay: float = 1.0) -> tuple[dict[str, str], dict[str, list[str]]]:
    """
    對每個 subdomain 查詢 Shodan 取得 http.html 和 product 內容
    
    查詢: hostname:"{subdomain}"
    從回傳的 matches[].http.html 取得 HTML 內容
    從回傳的 matches[].product 取得 product 內容
    
    Args:
        api_key: Shodan API Key
        subdomains: subdomain 清單
        delay: 每次查詢間的延遲秒數
    
    Returns:
        (html_result, product_result) 兩個字典
        - html_result: {fqdn: html} 字典
        - product_result: {fqdn: [product1, product2, ...]} 字典
    """
    import shodan
    import time
    
    api = shodan.Shodan(api_key)
    html_result: dict[str, str] = {}
    product_result: dict[str, list[str]] = {}
    
    for subdomain in subdomains:
        subdomain = subdomain.strip().lower()
        if not subdomain:
            continue
            
        query = f'hostname:"{subdomain}"'
        logger.debug(f"Shodan HTTP 查詢: {query}")
        
        try:
            search_result = api.search(query)
            total = search_result.get("total", 0)
            
            if total == 0:
                logger.debug(f"Shodan 無結果: {subdomain}")
                time.sleep(delay)
                continue
            
            # 合併所有 matches 的 http.html 和 product
            html_parts = []
            products = []
            relevant_matches = 0
            for match in search_result.get("matches", []):
                if not _match_belongs_to_target(match, subdomain):
                    continue

                relevant_matches += 1

                # 取得 http.html
                http_data = match.get("http", {})
                if http_data:
                    html = http_data.get("html", "")
                    if html:
                        html_parts.append(html)
                
                # 取得 product
                product = match.get("product", "")
                if product and product not in products:
                    products.append(product)

            if total and relevant_matches == 0:
                logger.warning(
                    f"[Shodan] {subdomain} 查到 {total} 筆，但無任何 match 能精確歸屬此 fqdn，已全部略過"
                )
            
            if html_parts:
                # 合併所有 html（用換行分隔）
                combined_html = "\n<!-- SHODAN_MATCH_SEPARATOR -->\n".join(html_parts)
                html_result[subdomain] = combined_html
                logger.info(f"[Shodan HTTP] {subdomain} 取得 {len(html_parts)} 筆 html")
            
            if products:
                product_result[subdomain] = products
                logger.info(f"[Shodan Product] {subdomain} 取得 {len(products)} 個 product: {products}")
            
            if not html_parts and not products:
                logger.debug(f"[Shodan] {subdomain} 無 html 或 product 資料")
            
            time.sleep(delay)
            
        except shodan.APIError as e:
            logger.error(f"Shodan API 錯誤 ({subdomain}): {e}")
        except Exception as e:
            logger.error(f"查詢失敗 ({subdomain}): {e}")
    
    logger.info(f"[Shodan] 共取得 {len(html_result)} 個 html, {len(product_result)} 個 product")
    return html_result, product_result