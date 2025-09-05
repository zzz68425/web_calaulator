"""
網路相關工具函數
"""
import time
from typing import Callable, Any

def rate_limit(delay: float):
    """速率限制裝飾器"""
    def decorator(func: Callable) -> Callable:
        last_called = [0.0] # 使用列表來保存最後呼叫時間，因為非本地變數不可變
        
        def wrapper(*args, **kwargs) -> Any: # 不知道被裝飾的函示有多少參數，所以用*args, **kwargs
            elapsed = time.time() - last_called[0]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result
        
        return wrapper
    return decorator
