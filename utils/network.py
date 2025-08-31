"""
網路相關工具函數
"""
import time
from typing import Callable, Any

def rate_limit(delay: float):
    """速率限制裝飾器"""
    def decorator(func: Callable) -> Callable:
        last_called = [0.0]
        
        def wrapper(*args, **kwargs) -> Any:
            elapsed = time.time() - last_called[0]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result
        
        return wrapper
    return decorator
