import requests
import json

# --- 設定區 ---
# 請替換成你自己的 OTX API Key
API_KEY = "13bcdb1daee03f75eab0e7f70e500e29ae295deb8a99257206d3a897d7ee202f"
# 你的目標主機名稱
hostname = "www.tncvs.tn.edu.tw"
# ---

def get_and_process_urls(target_hostname):
    """
    透過 API 查詢指定 hostname，並直接解析回應的 JSON 來提取 URL 及其狀態碼。
    """
    print(f"[*] 正在透過 API 查詢 Hostname: {target_hostname}...")
    
    # 組合 API 請求網址
    api_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{target_hostname}/url_list"
    headers = {"X-OTX-API-KEY": API_KEY}

    try:
        # 發送 API 請求
        resp = requests.get(api_url, headers=headers, timeout=15)
        
        # 確認請求是否成功
        resp.raise_for_status()

        # 將 API 回應的內容解析為 JSON (Python 中的字典格式)
        data = resp.json()
        
        # --- 新增：印出排版後的 JSON ---
        print("\n--- OTX API 回應的完整 JSON 內容 ---")
        print(json.dumps(data, indent=4, ensure_ascii=False))
        # ------------------------------------
        
        # 從解析後的資料中獲取 'url_list'
        url_list = data.get('url_list', [])

        if not url_list:
            print("[!] 在 OTX 回應中未找到任何關聯 URL。")
            return

        print("\n--- URL 及其在 OTX 紀錄中的 HTTP 狀態碼 ---")
        # 遍歷列表中的每一個項目
        for item in url_list:
            url = item.get('url', 'URL not found')
            
            # 智慧提取狀態碼的邏輯：
            # 1. 優先嘗試從頂層的 'httpcode' 欄位獲取。
            # 2. 如果不存在，則嘗試從巢狀的 'result' -> 'urlworker' -> 'http_code' 獲取。
            # 3. 如果兩者都不存在，則標示為 'N/A' (Not Available)。
            status_code = item.get('httpcode')
            if status_code is None:
                # 使用 .get() 鏈式調用來安全地存取深層的鍵
                status_code = item.get('result', {}).get('urlworker', {}).get('http_code')
            
            # 準備顯示用的狀態碼字串
            if status_code is None:
                status_code_display = 'N/A'
            else:
                status_code_display = str(status_code)
                
            # 為了對齊，讓狀態碼字串固定寬度
            print(f"[狀態: {status_code_display.ljust(4)}] {url}")

    except requests.exceptions.HTTPError as e:
        print(f"\n[!] API 請求失敗，狀態碼: {e.response.status_code}")
        print(f"[!] 錯誤訊息: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\n[!] 請求發生網路錯誤: {e}")
    except json.JSONDecodeError:
        print("\n[!] 錯誤：無法解析伺服器回應的 JSON。")

# --- 執行主程式 ---
if __name__ == "__main__":
    get_and_process_urls(hostname)