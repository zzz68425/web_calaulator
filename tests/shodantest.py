"""
ShodanScanner 模組測試程式
- 讓使用者輸入網域以測試 ShodanScanner
"""

import os
import sys
from dotenv import load_dotenv

# 從父目錄匯入 ShodanScanner
try:
    # 確保能從正確的路徑匯入模組
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from scanners.shodan_scanner import ShodanScanner
    from models.website import ShodanResult
except ImportError as e:
    print(f"錯誤：無法載入所需的模組。請確認檔案結構正確。", file=sys.stderr)
    print(f"詳細錯誤訊息: {e}", file=sys.stderr)
    sys.exit(1)

# 載入環境變數
load_dotenv()

def main():
    """主程式，處理使用者輸入與模組測試。"""
    
    print("=== Shodan 掃描器測試工具 ===")

    # 獲取 Shodan API 金鑰
    shodan_api_key = os.getenv("SHODAN_API_KEY")
    if not shodan_api_key:
        shodan_api_key = input("請輸入 Shodan API Key (或在 .env 檔中設定): ").strip()
    
    if not shodan_api_key:
        print("錯誤：未提供 Shodan API Key，程式終止。", file=sys.stderr)
        return

    # 獲取憑證 CN pattern
    cert_pattern = input("請輸入要查詢的網域 (例如: *.ntu.edu.tw): ").strip()
    if not cert_pattern:
        print("錯誤：未輸入網域，程式終止。", file=sys.stderr)
        return

    # 創建 ShodanScanner 實例
    scanner = ShodanScanner(api_key=shodan_api_key)

    # 執行掃描
    print(f"\n正在使用 ShodanScanner 查詢 {cert_pattern}...")
    result: ShodanResult = scanner.scan(
        cert_pattern=cert_pattern,
        country="TW",
        port="443"
    )

    # 顯示結果
    print("\n--- 查詢結果 ---")
    if result.total_results > 0:
        print(f"總共找到 {result.total_results} 筆結果。")
        print(f"解析後找到 {len(result.ips)} 個 IP 和 {len(result.domains)} 個域名。")
        
        print("\n找到的 IP：")
        for ip in result.ips:
            print(f"- {ip}")

        print("\n找到的域名：")
        for domain in result.domains:
            print(f"- {domain}")

    else:
        print("沒有找到符合條件的結果。")


if __name__ == "__main__":
    main()
