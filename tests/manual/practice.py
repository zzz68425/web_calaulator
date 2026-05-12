import threading
import time
import queue
import ipaddress
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import dns.resolver
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

#現在要做一個多執行續的網頁request範例練習


#新增單筆request
class Requester:
    def __init__(self):
        pass


    #request方法
    def fetch(self, url):
        try:
            response = requests.get(url, timeout=5, )
            return response.status_code
        except requests.RequestException as e:
            return f"error:{e}"
        

if __name__ == "__main__":
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.python.org",
        "https://www.stackoverflow.com",
        "https://www.reddit.com",
        "https://www.medium.com",
        "https://www.linkedin.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.instagram.com"
    ]

    req = Requester()
    fut = []
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=16) as ex:
        for u in urls:
            fut.append(ex.submit(req.fetch, u))
        for f in as_completed(fut):
            print(f.result())
    end_time = time.time()
    print(f"總共花費時間: {end_time - start_time:.2f} 秒")