"""
Shodan 掃描器模組
"""
import shodan
from typing import List, Set
from scanners.base import BaseScanner
from models.website import ShodanResult
from utils.logger import get_logger

logger = get_logger("scanners.shodan_scanner")



class ShodanScanner(BaseScanner):
    """Shodan 掃描器"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.api = shodan.Shodan(api_key)
    
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
        """解析 Shodan 結果"""
        result = ShodanResult()
        result.total_results = raw_results.get('total', 0)
        
        domains = set()
        ips = set()
        
        logger.info(f"找到 {result.total_results} 筆 Shodan 結果")
        
        for match in raw_results.get('matches', []):
            # 收集 IP
            ip = match.get('ip_str')
            if ip:
                ips.add(ip)
            
            # 從 hostnames 收集域名
            for hostname in match.get('hostnames', []):
                if self._is_valid_domain(hostname):
                    domains.add(hostname)
                    logger.debug(f"從 hostnames 找到: {hostname}")
            
            # 從憑證收集域名
            ssl_info = match.get('ssl', {})
            if ssl_info and 'cert' in ssl_info:
                cert_domains = self._extract_domains_from_cert(ssl_info['cert'])
                for domain in cert_domains:
                    logger.debug(f"從憑證找到: {domain}")
                domains.update(cert_domains)
        
        result.domains = list(domains)
        result.ips = list(ips)
        
        logger.info(f"解析結果: {len(result.domains)} 個域名, {len(result.ips)} 個 IP")
        for domain in result.domains:
            logger.info(f"域名: {domain}")
        
        return result
    
    def _extract_domains_from_cert(self, cert: dict) -> Set[str]:
        """從憑證提取域名"""
        domains = set()
        
        # 處理 Subject CN - Shodan 格式是列表
        subject = cert.get('subject', [])
        if isinstance(subject, list):
            # Shodan 返回格式: [['C', 'TW'], ['CN', '*.ptivs.tn.edu.tw'], ...]
            for item in subject:
                if isinstance(item, list) and len(item) >= 2:
                    if item[0] == 'CN':
                        domain = self._clean_domain(item[1])
                        if self._is_valid_domain(domain):
                            domains.add(domain)
                            logger.debug(f"Subject CN: {domain}")
        
        # 處理 Subject Alternative Names
        extensions = cert.get('extensions', [])
        if isinstance(extensions, list):
            for ext in extensions:
                # Shodan 的 extensions 格式
                if isinstance(ext, dict):
                    if ext.get('name') == 'subjectAltName':
                        # SAN 資料可能是字串格式 "DNS:*.example.com, DNS:example.com"
                        san_data = ext.get('data', '')
                        if san_data:
                            for san_item in san_data.split(','):
                                san_item = san_item.strip()
                                if san_item.startswith('DNS:'):
                                    domain = self._clean_domain(san_item[4:])
                                    if self._is_valid_domain(domain):
                                        domains.add(domain)
                                        logger.debug(f"SAN: {domain}")
        
        # 有時候 Shodan 把 extensions 放在不同格式
        # 備用解析方式
        if 'extensions' in cert and isinstance(cert['extensions'], dict):
            san_list = cert['extensions'].get('subjectAltName', [])
            if isinstance(san_list, list):
                for san_item in san_list:
                    if isinstance(san_item, str):
                        domain = self._clean_domain(san_item)
                        if self._is_valid_domain(domain):
                            domains.add(domain)
                            logger.debug(f"SAN (alt): {domain}")
        
        return domains
    
    def _clean_domain(self, domain: str) -> str:
        """清理域名"""
        if not domain:
            return ""
        
        domain = domain.strip()
        
        # 移除 wildcard
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # 移除 DNS: 前綴（如果有）
        if domain.startswith('DNS:'):
            domain = domain[4:]
        
        return domain.lower()
    
    def _is_valid_domain(self, domain: str) -> bool:
        """驗證域名是否有效"""
        if not domain or not isinstance(domain, str):
            return False
        
        domain = domain.strip().lower()
        
        # 檢查是否為 .edu.tw 域名
        if not domain.endswith('.edu.tw'):
            return False
        
        # 基本長度檢查
        if len(domain) < 8:  # 最短應該是 x.edu.tw
            return False
        
        # 檢查是否有非法字元
        import re
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        return True