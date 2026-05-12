"""
查詢 Shodan 特定 hostname 的完整資訊並匯出為 .log 檔
用法: python shodan_host_query.py <hostname>
範例: python shodan_host_query.py stu.med.ncku.edu.tw
"""
import os
import sys
import json
from datetime import datetime
import shodan
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')

if not SHODAN_API_KEY:
    print("錯誤：請在 .env 中設定 SHODAN_API_KEY")
    sys.exit(1)

api = shodan.Shodan(SHODAN_API_KEY)


def search_hostname(hostname: str, export: bool = True) -> dict:
    """
    查詢特定 hostname 在 Shodan 上的資訊
    
    Args:
        hostname: 要查詢的域名 (例如: stu.med.ncku.edu.tw)
        export: 是否匯出為 .log 檔
    
    Returns:
        Shodan API 回傳的結果
    """
    print("=" * 80)
    print(f"查詢 Hostname: {hostname}")
    print("=" * 80)
    
    try:
        # 方法 1: 用 hostname 搜尋
        query = f'hostname:"{hostname}"'
        print(f"查詢語法: {query}")
        
        results = api.search(query, page=1)
        total = results.get('total', 0)
        matches = results.get('matches', [])
        
        print(f"找到 {total} 筆結果")
        
        if not matches:
            # 方法 2: 嘗試用 ssl.cert.subject.cn 搜尋
            print("\n嘗試用憑證 CN 搜尋...")
            query2 = f'ssl.cert.subject.cn:"{hostname}"'
            results = api.search(query2, page=1)
            total = results.get('total', 0)
            matches = results.get('matches', [])
            print(f"找到 {total} 筆結果")
        
        # 準備匯出資料
        export_data = {
            'query_time': datetime.now().isoformat(),
            'hostname': hostname,
            'total': total,
            'matches': matches
        }
        
        # 匯出到 .log 檔
        if export:
            # 清理 hostname 作為檔名
            safe_hostname = hostname.replace('.', '_').replace(':', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_filename = f"shodan_{safe_hostname}_{timestamp}.log"
            
            with open(log_filename, 'w', encoding='utf-8') as f:
                f.write(f"Shodan Query Log\n")
                f.write(f"{'=' * 80}\n")
                f.write(f"Query Time: {export_data['query_time']}\n")
                f.write(f"Hostname: {hostname}\n")
                f.write(f"Total Results: {total}\n")
                f.write(f"{'=' * 80}\n\n")
                f.write("JSON Data:\n")
                f.write(json.dumps(export_data, indent=2, ensure_ascii=False, default=str))
            
            print(f"\n[OK] 已匯出到 {log_filename}")
        
        # 顯示摘要
        if matches:
            print("\n" + "-" * 40)
            print("結果摘要:")
            print("-" * 40)
            for i, match in enumerate(matches[:5], 1):
                ip = match.get('ip_str', 'N/A')
                port = match.get('port', 'N/A')
                os_info = match.get('os', 'N/A')
                http = match.get('http', {})
                title = http.get('title', 'N/A') if http else 'N/A'
                
                print(f"\n[{i}] IP: {ip}:{port}")
                print(f"    OS: {os_info}")
                print(f"    Title: {title}")
                
                # 檢查 IoT 指標
                iot_indicators = []
                data = match.get('data', '').lower()
                os_str = str(os_info).lower() if os_info else ''
                
                for kw in ['synology', 'qnap', 'nas', 'mikrotik', 'embedded', 'printer', 'camera']:
                    if kw in os_str or kw in data:
                        iot_indicators.append(kw)
                
                if iot_indicators:
                    print(f"    [!] IoT 指標: {iot_indicators}")
                
                # 檢查登入頁面
                html = http.get('html', '').lower() if http else ''
                if 'type="password"' in html or "type='password'" in html:
                    print(f"    [!] 偵測到登入表單")
        else:
            print("\n[!] 未找到任何結果")
        
        return export_data
        
    except shodan.APIError as e:
        print(f"API 錯誤: {e}")
        return {}


def lookup_ip(ip: str, export: bool = True) -> dict:
    """
    直接查詢特定 IP 的所有資訊 (使用 host API)
    
    Args:
        ip: IP 位址
        export: 是否匯出為 .log 檔
    
    Returns:
        Shodan API 回傳的 host 資訊
    """
    print("=" * 80)
    print(f"查詢 IP: {ip}")
    print("=" * 80)
    
    try:
        host = api.host(ip)
        
        print(f"IP: {host.get('ip_str', 'N/A')}")
        print(f"OS: {host.get('os', 'N/A')}")
        print(f"Org: {host.get('org', 'N/A')}")
        print(f"Hostnames: {host.get('hostnames', [])}")
        print(f"Ports: {host.get('ports', [])}")
        
        # 匯出到 .log 檔
        if export:
            safe_ip = ip.replace('.', '_').replace(':', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_filename = f"shodan_ip_{safe_ip}_{timestamp}.log"
            
            export_data = {
                'query_time': datetime.now().isoformat(),
                'ip': ip,
                'host_data': host
            }
            
            with open(log_filename, 'w', encoding='utf-8') as f:
                f.write(f"Shodan IP Lookup Log\n")
                f.write(f"{'=' * 80}\n")
                f.write(f"Query Time: {export_data['query_time']}\n")
                f.write(f"IP: {ip}\n")
                f.write(f"{'=' * 80}\n\n")
                f.write("JSON Data:\n")
                f.write(json.dumps(export_data, indent=2, ensure_ascii=False, default=str))
            
            print(f"\n[OK] 已匯出到 {log_filename}")
        
        return host
        
    except shodan.APIError as e:
        print(f"API 錯誤: {e}")
        return {}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("=" * 60)
        print("Shodan Hostname/IP 查詢工具")
        print("=" * 60)
        print("\n用法:")
        print("  查詢 hostname: python shodan_host_query.py <hostname>")
        print("  查詢 IP:       python shodan_host_query.py -ip <ip>")
        print("\n範例:")
        print("  python shodan_host_query.py stu.med.ncku.edu.tw")
        print("  python shodan_host_query.py -ip 140.116.60.225")
        print("\n結果會自動匯出為 .log 檔案")
        sys.exit(1)
    
    if sys.argv[1] == '-ip' and len(sys.argv) >= 3:
        # IP 查詢模式
        lookup_ip(sys.argv[2])
    else:
        # Hostname 查詢模式
        search_hostname(sys.argv[1])
