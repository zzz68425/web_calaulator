"""
VirusTotal 掃描器模組
"""
import requests
from typing import List
import logging
from scanners.base import BaseScanner

logger = logging.getLogger(__name__)

class VirusTotalScanner(BaseScanner):
    """VirusTotal 掃描器"""
    
    BASE_URL = "https://www.virustotal.com/vtapi/v2"
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
    
    def scan(self, domain: str) -> List[str]:
        """查詢域名的子域名"""
        return self.get_subdomains(domain)
    
    def get_subdomains(self, domain: str) -> List[str]:
        """獲取子域名"""
        logger.info(f"查詢 VirusTotal 子域名: {domain}")
        
        url = f"{self.BASE_URL}/domain/report"
        params = {
            'apikey': self.api_key,
            'domain': domain
        }
        
        try:
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                return self.parse_results(response.json())
            elif response.status_code == 204:
                logger.warning("VirusTotal API 配額已用完")
            elif response.status_code == 403:
                logger.error("VirusTotal API Key 無效")
            else:
                logger.error(f"HTTP 錯誤: {response.status_code}")
                
        except Exception as e:
            logger.error(f"查詢失敗: {e}")
        
        return []
    
    def parse_results(self, raw_results: dict) -> List[str]:
        """解析 VirusTotal 結果"""
        if raw_results.get('response_code') == 1:
            subdomains = raw_results.get('subdomains', [])
            logger.info(f"找到 {len(subdomains)} 個子域名")
            return sorted(subdomains)
        else:
            logger.warning(f"域名未找到: {raw_results.get('verbose_msg', 'Unknown')}")
            return []