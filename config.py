"""
配置檔案 - 管理所有設定參數
"""
import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

load_dotenv()  # 載入 .env 檔案

@dataclass
class Config:
    """應用程式配置"""
    # API Keys
    SHODAN_API_KEY: str = os.getenv('SHODAN_API_KEY', '')
    VIRUSTOTAL_API_KEY: str = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # 資料庫設定
    DATABASE_PATH: str = 'website.db'
    
    # 網路設定
    REQUEST_TIMEOUT: int = 10
    REQUEST_DELAY: float = 1.0
    VT_API_DELAY: float = 2.0

    VALIDATOR_MAX_WORKERS: int = 16          # 驗證階段同時併發數
    CONNECT_TIMEOUT: float = 5.0             # TCP 連線逾時（秒）
    READ_TIMEOUT: float = 7.0                # 回應讀取逾時（秒）
    HTTP_POOL_SIZE: int = 64                 # 連線池大小（每執行緒）
    HTTP_RETRIES: int = 2                    # 臨時錯誤重試次數
    
    # User Agent
    USER_AGENT: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    # 搜尋設定
    DEFAULT_COUNTRY: str = 'TW'
    DEFAULT_PORT: str = '443'
    
    @classmethod
    def from_env(cls) -> 'Config':
        """從環境變數載入配置"""
        return cls()
    
    def validate(self) -> bool:
        """驗證配置是否有效"""
        if not self.SHODAN_API_KEY:
            raise ValueError("SHODAN_API_KEY 未設定")
        if not self.VIRUSTOTAL_API_KEY:
            raise ValueError("VIRUSTOTAL_API_KEY 未設定")
        return True