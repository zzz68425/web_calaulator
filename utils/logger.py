"""
日誌管理模組
"""
import os
import logging
from datetime import datetime

# 建立 logs 資料夾
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_dir = os.path.join(base_dir, "logs")
os.makedirs(log_dir, exist_ok=True)

# 建立日誌檔名
now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = os.path.join(log_dir, f"website_finder_{now_str}.log")

# 建立 logger
logger = logging.getLogger("website_finder")
logger.setLevel(logging.INFO)

# 避免重複加 handler
if not logger.handlers:
    # 建立 formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )
    
    # File handler
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def get_logger(name=None):
    """取得 logger"""
    if name:
        return logging.getLogger(f"website_finder.{name}")
    return logger