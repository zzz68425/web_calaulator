"""
Shodan 掃描器模組
- 使用 Shodan 頂層 domains 欄位提取網域
- 移除憑證解析邏輯以簡化程式碼
"""

import shodan
import re
from typing import List, Set, Optional
from scanners.base import BaseScanner
from models.website import ShodanResult
from utils.logger import get_logger
from database.repository import DatabaseManagerORM

logger = get_logger("scanners.shodan_scanner")

class ShodanScanner(BaseScanner):
    """Shodan 掃描器"""
    
    def __init__(self, api_key: str, db_manager: Optional[DatabaseManagerORM] = None):
        super().__init__(api_key)
        self.api = shodan.Shodan(api_key)
        self.db_manager = db_manager
    
    def scan(self, cert_pattern: str, country: str = "TW", port: str = "443") -> ShodanResult:
        """搜尋特定憑證模式"""
        query = f'port:"{port}" country:"{country}" ssl.cert.subject.cn:"{cert_pattern}"'
        logger.info(f"Shodan 查詢: {query}")
        
        try:
            results = self.api.search(query)
            return self.parse_results(results)
        except shodan.APIError as e:
            logger.error(f"Shodan API 錯誤: {e}")
            return ShodanResult()
        except Exception as e:
            logger.error(f"搜尋失敗: {e}")
            return ShodanResult()

    def parse_results(self, raw_results: dict) -> ShodanResult:
        """解析 Shodan 結果，從 domains 欄位提取 .edu.tw 網域，並處理 hostname 欄位"""
        result = ShodanResult()
        result.total_results = raw_results.get('total', 0)
        
        domains: Set[str] = set()
        ips: Set[str] = set()
        vt_targets: Set[str] = set()
        
        logger.info(f"找到 {result.total_results} 筆 Shodan 結果")
        
        for match in raw_results.get('matches', []):
            # 收集 IP
            ip = match.get('ip_str')
            if ip:
                ips.add(ip)
            
            collected_this_match: Set[str] = set()

            # 1) 從 domains 欄位收集網域，只保留 .edu.tw
            for d in match.get('domains', []) or []:
                if isinstance(d, str):
                    clean_d = self._clean_domain(d)
                    if self._is_valid_domain(clean_d):
                        collected_this_match.add(clean_d)
                        logger.debug(f"從 domains 找到: {clean_d}")

            # 2) 補充：從 hostnames 欄位收集
            if not collected_this_match:
                for h in match.get('hostnames', []) or []:
                    if isinstance(h, str):
                        clean_h = self._clean_domain(h)
                        if self._is_valid_domain(clean_h):
                            collected_this_match.add(clean_h)
                            logger.debug(f"從 hostnames 找到: {clean_h}")

            # 3) 補充：從憑證 CN/SAN 收集（ssl.cert）
            if not collected_this_match:
                ssl_info = match.get('ssl', {}) or {}
                cert = ssl_info.get('cert')
                if isinstance(cert, dict):
                    cert_domains = self._extract_domains_from_cert(cert)
                    for cd in cert_domains:
                        if self._is_valid_domain(cd):
                            collected_this_match.add(cd)
                            logger.debug(f"從 ssl.cert 找到: {cd}")

            # 合併到總集合
            domains.update(collected_this_match)
            
            # institution 比對與 VT 目標
            for clean_d in collected_this_match:
                if self.db_manager and self.db_manager.find_institution_domain(clean_d):
                    hostnames = match.get('hostnames', []) or []
                    logger.debug(f"institution 命中 {clean_d}，hostnames={hostnames}")
                    hostname_target = self._extract_subdomain_from_hostname(hostnames, clean_d)
                    if hostname_target:
                        vt_targets.add(hostname_target)
                        logger.info(f"institution 匹配: {clean_d} -> 從 hostname 提取: {hostname_target}")
                    else:
                        vt_targets.add(clean_d)
                        logger.info(f"institution 匹配但無法從 hostname 提取: {clean_d}")
                else:
                    vt_targets.add(clean_d)
                    logger.debug(f"無 institution 匹配: {clean_d}")
        
        result.domains = list(domains)
        result.ips = list(ips)
        result.vt_query_targets = list(vt_targets)
        
        logger.info(f"解析結果: {len(result.domains)} 個域名, {len(result.ips)} 個 IP")
        logger.info(f"VirusTotal 查詢目標: {len(result.vt_query_targets)} 個")
        for domain in result.domains:
            logger.info(f"域名: {domain}")
        for target in result.vt_query_targets:
            logger.info(f"VT目標: {target}")
            
        return result

    def _extract_subdomain_from_hostname(self, hostnames: List[str], institution_domain: str) -> Optional[str]:
        """從 hostname 中擷取『剛好多一段前綴 + institution.domain』
        規則：若 hostname 含 institution.domain，取其左側『最後一段』加回去。
        例：
          - ptivs.tn.edu.tw  + tn.edu.tw  -> ptivs.tn.edu.tw
          - www.tntcsh.tn.edu.tw + tn.edu.tw -> tntcsh.tn.edu.tw
          - cctw.tnssh.tn.edu.tw + tn.edu.tw -> tnssh.tn.edu.tw
        """
        inst_labels = institution_domain.split('.')
        for hostname in hostnames:
            if not isinstance(hostname, str):
                continue
            h = hostname.strip().lower()
            if not h or '.' not in h:
                continue

            h_labels = h.split('.')
            # 需至少有一段在 inst 左側
            if len(h_labels) <= len(inst_labels):
                continue
            # 尾端對齊
            if h_labels[-len(inst_labels):] != inst_labels:
                continue

            prefix_labels = h_labels[: -len(inst_labels)]
            if not prefix_labels:
                continue

            # 只取『最後一段』作為前綴
            last_prefix = prefix_labels[-1]
            result = last_prefix + '.' + institution_domain
            return result

        return None

    def _extract_domains_from_cert(self, cert: dict) -> Set[str]:
        domains: Set[str] = set()
        # Subject CN - Shodan 通常是 list of lists
        subject = cert.get('subject', [])
        if isinstance(subject, list):
            for item in subject:
                if isinstance(item, list) and len(item) >= 2 and item[0] == 'CN':
                    cn = self._clean_domain(item[1])
                    if cn:
                        domains.add(cn)
        # SAN in extensions (多種格式)
        extensions = cert.get('extensions')
        if isinstance(extensions, list):
            for ext in extensions:
                if isinstance(ext, dict) and ext.get('name') == 'subjectAltName':
                    san_data = ext.get('data', '')
                    if isinstance(san_data, str):
                        for token in san_data.split(','):
                            token = token.strip()
                            if token.startswith('DNS:'):
                                san = self._clean_domain(token[4:])
                                if san:
                                    domains.add(san)
        elif isinstance(extensions, dict):
            san_list = extensions.get('subjectAltName', [])
            if isinstance(san_list, list):
                for san in san_list:
                    if isinstance(san, str):
                        domains.add(self._clean_domain(san))
        return {d for d in domains if d}

    def _clean_domain(self, domain: str) -> str:
        if not isinstance(domain, str):
            return ""
        d = domain.strip()
        if d.startswith('*.'):
            d = d[2:]
        if d.startswith('DNS:'):
            d = d[4:]
        return d.lower()

    def _is_valid_domain(self, domain: str) -> bool:
        if not domain:
            return False
        if not domain.endswith('.edu.tw'):
            return False
        if len(domain) < 8:
            return False
        import re as _re
        return bool(_re.match(r'^[a-z0-9.-]+$', domain))