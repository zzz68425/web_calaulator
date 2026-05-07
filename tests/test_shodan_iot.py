"""
測試腳本：從 Shodan 查詢特定 subdomain 的詳細資訊
用來分析 IoT UI 或登入頁面的特徵
"""
import os
import json
import shodan
from dotenv import load_dotenv

load_dotenv()

# 取得 API Key
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')

if not SHODAN_API_KEY:
    print("錯誤：請在 .env 中設定 SHODAN_API_KEY")
    exit(1)

api = shodan.Shodan(SHODAN_API_KEY)


def search_by_query(query: str, max_results: int = 5):
    """
    用 Shodan 搜尋查詢，回傳詳細資訊
    """
    print("=" * 80)
    print(f"查詢: {query}")
    print("=" * 80)
    
    try:
        results = api.search(query, page=1)
        total = results.get('total', 0)
        print(f"\n總筆數: {total}")
        
        matches = results.get('matches', [])
        
        for i, match in enumerate(matches[:max_results], 1):
            print(f"\n{'=' * 40}")
            print(f"[結果 {i}]")
            print(f"{'=' * 40}")
            
            # 基本資訊
            print(f"\n[基本資訊]")
            print(f"  IP: {match.get('ip_str', 'N/A')}")
            print(f"  Port: {match.get('port', 'N/A')}")
            print(f"  Transport: {match.get('transport', 'N/A')}")
            
            # 作業系統 (重要！可以識別 IoT)
            os_info = match.get('os', None)
            if os_info:
                print(f"  OS: {os_info}")
            
            # 組織資訊
            print(f"  Org: {match.get('org', 'N/A')}")
            print(f"  ISP: {match.get('isp', 'N/A')}")
            
            # 域名資訊
            domains = match.get('domains', [])
            hostnames = match.get('hostnames', [])
            print(f"\n[域名資訊]")
            print(f"  Domains: {domains}")
            print(f"  Hostnames: {hostnames}")
            
            # SSL 憑證資訊
            ssl = match.get('ssl', {})
            if ssl:
                cert = ssl.get('cert', {})
                print(f"\n[SSL 憑證]")
                print(f"  Subject CN: {cert.get('subject', {}).get('CN', 'N/A')}")
                print(f"  Issuer: {cert.get('issuer', {}).get('O', 'N/A')}")
                
                # Subject Alt Names (SAN)
                extensions = cert.get('extensions', [])
                for ext in extensions:
                    if ext.get('name') == 'subjectAltName':
                        print(f"  SAN: {ext.get('data', 'N/A')[:100]}...")
            
            # HTTP 資訊 (重要！可以識別登入頁面)
            http = match.get('http', {})
            if http:
                print(f"\n[HTTP 資訊]")
                print(f"  Title: {http.get('title', 'N/A')}")
                print(f"  Server: {http.get('server', 'N/A')}")
                print(f"  Status: {http.get('status', 'N/A')}")
                
                # HTML 內容預覽
                html = http.get('html', '')
                if html:
                    # 檢查是否有登入表單特徵
                    html_lower = html.lower()
                    login_features = []
                    if 'type="password"' in html_lower or "type='password'" in html_lower:
                        login_features.append('password input')
                    if 'login' in html_lower:
                        login_features.append('login keyword')
                    if 'signin' in html_lower or 'sign-in' in html_lower:
                        login_features.append('signin keyword')
                    if '<form' in html_lower and ('user' in html_lower or 'password' in html_lower):
                        login_features.append('login form')
                    
                    if login_features:
                        print(f"  登入特徵: {login_features}")
                    
                    print(f"  HTML 長度: {len(html)} bytes")
                    print(f"  HTML 預覽: {html[:200]}...")
            
            # Product/Vendor 資訊 (可識別 IoT)
            product = match.get('product', None)
            vendor = match.get('vendor', None)
            if product or vendor:
                print(f"\n[產品資訊]")
                print(f"  Product: {product}")
                print(f"  Vendor: {vendor}")
            
            # 原始 Banner (完整回傳內容)
            data = match.get('data', '')
            if data:
                print(f"\n[Banner 預覽]")
                print(f"  {data[:300]}...")
            
            # 檢測 IoT 特徵
            iot_indicators = []
            data_lower = data.lower() if data else ''
            os_str = str(os_info).lower() if os_info else ''
            title = http.get('title', '').lower() if http else ''
            
            # IoT 關鍵字檢測
            iot_keywords = [
                'synology', 'qnap', 'nas', 'diskstation', 'dsm',
                'embedded', 'router', 'switch', 'mikrotik', 'fortinet',
                'hikvision', 'dahua', 'camera', 'dvr', 'nvr',
                'printer', 'laserjet', 'xerox', 'epson',
                'ilo', 'idrac', 'ipmi', 'bmc'
            ]
            
            for kw in iot_keywords:
                if kw in os_str or kw in data_lower or kw in title:
                    iot_indicators.append(kw)
            
            if iot_indicators:
                print(f"\n[⚠️ IoT 指標]")
                print(f"  偵測到: {iot_indicators}")
        
        return results
        
    except shodan.APIError as e:
        print(f"API 錯誤: {e}")
        return None


def lookup_host(ip_or_domain: str):
    """
    直接查詢特定 IP 或 hostname 的資訊
    """
    print("=" * 80)
    print(f"查詢主機: {ip_or_domain}")
    print("=" * 80)
    
    try:
        # 如果是域名，先用 DNS 解析
        if not ip_or_domain.replace('.', '').isdigit():
            dns_result = api.dns.resolve(ip_or_domain)
            print(f"\nDNS 解析結果: {dns_result}")
            if ip_or_domain in dns_result:
                ip = dns_result[ip_or_domain]
                print(f"  {ip_or_domain} -> {ip}")
                ip_or_domain = ip
        
        # 查詢主機資訊
        host = api.host(ip_or_domain)
        
        print(f"\n[主機資訊]")
        print(f"  IP: {host.get('ip_str', 'N/A')}")
        print(f"  OS: {host.get('os', 'N/A')}")
        print(f"  Org: {host.get('org', 'N/A')}")
        print(f"  Hostnames: {host.get('hostnames', [])}")
        print(f"  Ports: {host.get('ports', [])}")
        
        # 每個服務的資訊
        for service in host.get('data', []):
            print(f"\n[Port {service.get('port')}]")
            print(f"  Product: {service.get('product', 'N/A')}")
            print(f"  Version: {service.get('version', 'N/A')}")
            
            http = service.get('http', {})
            if http:
                print(f"  HTTP Title: {http.get('title', 'N/A')}")
                print(f"  HTTP Server: {http.get('server', 'N/A')}")
        
        return host
        
    except shodan.APIError as e:
        print(f"API 錯誤: {e}")
        return None


def show_full_json(query: str, max_results: int = 1, export_file: str = None):
    """
    顯示 Shodan 查詢結果的完整 JSON
    可選擇匯出到檔案
    """
    print("=" * 80)
    print(f"查詢: {query}")
    print("=" * 80)
    
    try:
        results = api.search(query, page=1)
        total = results.get('total', 0)
        print(f"\n總筆數: {total}")
        
        matches = results.get('matches', [])
        
        # 匯出到檔案
        if export_file:
            with open(export_file, 'w', encoding='utf-8') as f:
                export_data = {
                    'query': query,
                    'total': total,
                    'matches': matches[:max_results] if max_results else matches
                }
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            print(f"\n[OK] 已匯出 {len(export_data['matches'])} 筆結果到 {export_file}")
        
        # 顯示在終端機
        for i, match in enumerate(matches[:max_results], 1):
            print(f"\n{'=' * 80}")
            print(f"[結果 {i}] 完整 JSON")
            print("=" * 80)
            print(json.dumps(match, indent=2, ensure_ascii=False, default=str))
        
        return results
    except shodan.APIError as e:
        print(f"API 錯誤: {e}")
        return None


if __name__ == "__main__":
    import sys
    
    # 如果有傳入參數，顯示完整 JSON
    if len(sys.argv) > 1:
        query = ' '.join(sys.argv[1:])
        show_full_json(query)
        exit(0)
    
    # 預設測試：顯示一筆 Synology NAS 的完整 JSON
    print("\n" + "=" * 80)
    print("顯示一筆 Synology NAS 的完整 JSON")
    print("=" * 80)
    
    synology_query = 'country:"TW" ssl.cert.subject.cn:"ncku.edu.tw" os:"Synology DiskStation"'
    show_full_json(synology_query, max_results=10, export_file='shodan_synology_export.json')
