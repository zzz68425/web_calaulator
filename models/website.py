"""
網站資料模型
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

@dataclass
class Website:
    """網站資訊模型"""
    fqdn: str
    ip: str
    url: Optional[str] = None
    protocol: Optional[str] = None
    status_code: Optional[int] = None
    redirect_to: Optional[str] = None
    title: Optional[str] = None
    when_crawled: datetime = field(default_factory=datetime.now)
    
    def __str__(self) -> str:
        return f"{self.url or self.fqdn} ({self.ip})"
    
    def to_dict(self) -> dict:
        """轉換為字典格式"""
        return {
            'fqdn': self.fqdn,
            'ip': self.ip,
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