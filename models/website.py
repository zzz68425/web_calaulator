"""
網站資料模型
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

@dataclass
class Website:
    """網站資訊模型（支援雙協定 IPv4/IPv6）"""
    fqdn: str
    url: Optional[str] = None
    protocol: Optional[str] = None
    status_code: Optional[int] = None
    redirect_to: Optional[str] = None
    title: Optional[str] = None
    when_crawled: datetime = field(default_factory=datetime.now)
    
    @property
    def ip(self) -> str:
        """動態回傳代表性 IP（優先 IPv4，其次 IPv6，最後佔位）"""
        ipv4 = getattr(self, 'ipv4', None)
        ipv6 = getattr(self, 'ipv6', None)
        return ipv4 or ipv6 or "0.0.0.0"
    
    def __str__(self) -> str:
        return f"{self.url or self.fqdn} ({self.ip})"
    
    def to_dict(self) -> dict:
        """轉換為字典格式"""
        return {
            'fqdn': self.fqdn,
            'ip': self.ip,  # 自動從 ipv4/ipv6 取得
            'ipv4': getattr(self, 'ipv4', None),
            'ipv6': getattr(self, 'ipv6', None),
            'url': self.url,
            'protocol': self.protocol,
            'status_code': self.status_code,
            'redirect_to': self.redirect_to,
            'title': self.title,
            'when_crawled': self.when_crawled.isoformat()
        }

@dataclass
class ShodanResult:
    """Shodan 搜尋結果"""
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    total_results: int = 0
    vt_query_targets: List[str] = field(default_factory=list)  # 用於 VirusTotal 查詢的目標網域