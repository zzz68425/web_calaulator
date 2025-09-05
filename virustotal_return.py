import requests
import time
from config import Config

class VirusTotalV3:
    """VirusTotal API v3 客戶端（僅保留子域名查詢）"""

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    def get_domain_subdomains(self, domain, limit=100):
        """獲取子域名列表 (API v3) - 支援分頁"""
        print(f"\n📋 查詢子域名 (目標: {limit} 個)...")
        
        url = f"{self.base_url}/domains/{domain}/subdomains"
        all_subdomains = []
        cursor = None
        page = 1
        total_count = None  # API 提供的總數
        has_more = False
        
        while True:
            params = {"limit": 40}  # 固定使用最大值
            if cursor:
                params["cursor"] = cursor
            
            try:
                print(f"   第 {page} 頁 (已獲取 {len(all_subdomains)} 個)...")
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # 嘗試獲取總數（如果 API 提供）
                    meta = data.get('meta', {})
                    if 'count' in meta and total_count is None:
                        total_count = meta.get('count')
                        print(f"      API 顯示總共有: {total_count} 個子域名")
                    
                    # 提取子域名
                    page_subdomains = []
                    for item in data.get('data', []):
                        subdomain_id = item.get('id', '')
                        if subdomain_id and subdomain_id not in all_subdomains:
                            all_subdomains.append(subdomain_id)
                            page_subdomains.append(subdomain_id)
                    
                    print(f"      本頁獲取: {len(page_subdomains)} 個")
                    
                    # 檢查是否有下一頁
                    links = data.get('links', {})
                    next_link = links.get('next')
                    
                    if not next_link:
                        print(f"   📌 已到最後一頁")
                        has_more = False
                        break
                    
                    if len(all_subdomains) >= limit:
                        print(f"   📌 已達到請求數量限制 ({limit} 個)")
                        has_more = True
                        break
                    
                    # 提取 cursor
                    from urllib.parse import urlparse, parse_qs
                    parsed_url = urlparse(next_link)
                    query_params = parse_qs(parsed_url.query)
                    new_cursor = query_params.get('cursor', [None])[0]
                    
                    if new_cursor and new_cursor != cursor:
                        cursor = new_cursor
                        page += 1
                        print(f"      等待 15 秒（避免速率限制）...")
                        time.sleep(15)
                    else:
                        break
                        
                elif response.status_code == 429:
                    print("   ⏰ 速率限制，等待 60 秒...")
                    time.sleep(60)
                    continue
                elif response.status_code == 404:
                    print(f"   ❌ 域名未找到或沒有子域名")
                    break
                else:
                    print(f"   ❌ 錯誤: {response.status_code}")
                    break
                    
            except Exception as e:
                print(f"   ❌ 查詢失敗: {e}")
                break
        
        # 結果統計
        print(f"\n   📊 統計:")
        print(f"      獲取結果: {len(all_subdomains)} 個")
        if total_count:
            print(f"      API 總數: {total_count} 個")
            if len(all_subdomains) < total_count:
                print(f"      未獲取: {total_count - len(all_subdomains)} 個")
        if has_more:
            print(f"      ℹ️ 還有更多資料（增加 limit 參數以獲取）")
        
        return all_subdomains
# 調整後的 main 函式
def main():
    # API Key 設定
    VT_API_KEY = Config.VIRUSTOTAL_API_KEY

    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        print("❌ 請設定 VirusTotal API Key (VT_API_KEY)")
        return

    client = VirusTotalV3(VT_API_KEY)

    print("🔍 VirusTotal API v3 - 子域名查詢工具")
    domain = input("請輸入域名: ").strip()

    if domain:
        # 這裡將 limit 參數設為 None 或一個極大的數
        # 讓 get_domain_subdomains 函式執行到沒有下一頁為止
        subdomains = client.get_domain_subdomains(domain, limit=999)
        
        if subdomains:
            print(f"\n📋 子域名列表 ({len(subdomains)} 個):")
            for i, subdomain in enumerate(subdomains, 1):
                print(f"   {i:3d}. {subdomain}")

if __name__ == "__main__":
    main()