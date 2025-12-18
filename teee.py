import requests
import json
import sys
from datetime import datetime

def query_crtsh_api(domain_pattern):
    """
    使用更穩定的 /json API 端點查詢 crt.sh
    (根據使用者建議，避免 503 錯誤)
    """
    
    # --- 參數更新 ---
    # 1. 使用您建議的 /json 專用端點
    url = "https://crt.sh/json?cn=ntu.edu.tw&exclude=expired" 
    

    # ------------------
    
    print(f"Querying crt.sh /json endpoint with cn={domain_pattern} (excluding expired)", file=sys.stderr)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
        }
        
        # 查詢範圍大，保持 30 秒超時
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status() 
        
        data = response.json()
        
        # 格式化後回傳 (pretty print)，ensure_ascii=False 確保中文正常顯示
        return json.dumps(data, indent=2, ensure_ascii=False)
        
    except requests.exceptions.Timeout:
        print("API request timed out. (30 seconds)", file=sys.stderr)
        return "[]"
    except requests.exceptions.RequestException as e:
        # 這裡可以捕捉到 503 (Service Unavailable) 錯誤
        print(f"API request failed: {e}", file=sys.stderr)
        return "[]"
    except json.JSONDecodeError:
        print("Failed to decode JSON response from crt.sh. Response was:", file=sys.stderr)
        print(response.text, file=sys.stderr)
        return "[]"

# --- 程式執行入口 ---
if __name__ == "__main__":
    
    pattern = "%.ncku.edu.tw" # 您最初的查詢目標
    log_filename = "crtsh_query.log" 

    # 1. 執行 API 查詢
    # 紀錄開始時間
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    json_output = query_crtsh_api(pattern)

    # 紀錄結束時間
    timestamp_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    
    # 2. 仍然將 JSON 結果印到螢幕上 (標準輸出)
    print(json_output)
    
    # 3. 嘗試將結果存入日誌檔案
    try:
        with open(log_filename, 'a', encoding='utf-8') as f:
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # 更新日誌標頭，反映新的查詢方式
            f.write(f"\n--- [Query Log (JSON Endpoint): {timestamp} | Pattern: {pattern} | Exclude: Expired] ---\n")
            f.write(json_output)
            f.write("\n--- [End of Log] ---\n")
            
        print(f"\n[日誌] 查詢結果已成功附加到檔案: {log_filename}", file=sys.stderr)
        print(f"\n[查詢時間] 開始: {timestamp} | 結束: {timestamp_end}\n", file=sys.stderr)
        
    except Exception as e:
        print(f"\n[日誌] 儲存日誌檔案失敗: {e}", file=sys.stderr)