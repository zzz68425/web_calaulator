"""
掃描器基礎類別
"""
from abc import ABC, abstractmethod
from typing import Any, List, Dict
import logging

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """掃描器基礎抽象類別"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.results = []
    
    @abstractmethod
    def scan(self, target: str) -> Any:
        """執行掃描"""
        pass
    
    @abstractmethod
    def parse_results(self, raw_results: Any) -> List[Dict]:
        """解析結果"""
        pass
    
    def clear_results(self) -> None:
        """清除結果"""
        self.results = []