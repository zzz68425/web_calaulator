#!/usr/bin/env python3
"""
Shodan 子網域統計工具
查詢並統計特定域名下的所有子網域數量
"""

import shodan
import time
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
import re
import os
from dotenv import load_dotenv
load_dotenv()

class ShodanSubdomainCounter:
    """Shodan 子網域統計器"""
    
    def __init__(self, api_key: str):
        """初始化"""
        self.api = shodan.Shodan(api_key)
        self.subdomains = set()
        self.subdomain_ips = defaultdict(set)  # 每個子域名對應的 IP
        self.subdomain_ports = defaultdict(set)  # 每個子域名開放的端口
        
    def search_domain(self, domain: str, get_all: bool = False) -> Dict:
        """
        搜尋域名的所有子網域
        
        Args:
            domain: 要查詢的主域名 (例如: tn.edu.tw)
            get_all: 是否嘗試獲取全部結果
        
        Returns:
            統計結果字典
        """
        print(f"{'='*60}")
        print(f"Shodan 子網域統計工具")
        print(f"目標域名: {domain}")
        print(f"{'='*60}\n")
        
        # 建構搜尋查詢
        query = f'hostname:".{domain}"'
        print(f"🔍 搜尋查詢: {query}")
        
        try:
            # 先查詢總數
            results = self.api.search(query, limit=1)
            total = results.get('total', 0)
            print(f"📊 總共找到 {total} 筆結果")
            
            if total == 0:
                print("❌ 沒有找到任何結果")
                return {}
            
            # 檢查 API 限制
            api_info = self.api.info()
            query_credits = api_info.get('query_credits', 0)
            scan_credits = api_info.get('scan_credits', 0)
            
            print(f"📊 API 配額資訊:")
            print(f"   查詢點數: {query_credits}")
            print(f"   掃描點數: {scan_credits}")
            
            # 決定要查詢的筆數
            if get_all:
                # 嘗試獲取全部，但考慮 API 限制
                max_results = min(total, 10000)  # 最多 10000 筆
                
                if total > 100:
                    print(f"\n⚠️ 注意：")
                    print(f"   總共有 {total} 筆結果")
                    print(f"   免費帳號最多只能取得 100 筆")
                    print(f"   付費帳號可以取得更多")
                    
                    if query_credits > 0:
                        confirm = input(f"\n要嘗試獲取全部 {min(total, max_results)} 筆嗎？(y/N): ").strip().lower()
                        if confirm != 'y':
                            max_results = 100
                    else:
                        print(f"   查詢點數不足，只能取得前 100 筆")
                        max_results = 100
                
                limit = max_results
            else:
                # 預設查詢前 100 筆
                limit = min(total, 100)
            
            print(f"\n⏳ 正在查詢前 {limit} 筆結果...")
            
            # 分頁查詢以獲取更多結果
            all_matches = []
            page = 1
            retrieved = 0
            
            while retrieved < limit:
                try:
                    page_size = min(100, limit - retrieved)
                    print(f"   第 {page} 頁 (已獲取 {retrieved}/{limit})...")
                    
                    # 使用分頁
                    page_results = self.api.search(query, page=page, limit=page_size)
                    matches = page_results.get('matches', [])
                    
                    if not matches:
                        break
                    
                    all_matches.extend(matches)
                    retrieved += len(matches)
                    page += 1
                    
                    # 避免太快
                    if retrieved < limit:
                        time.sleep(1)
                    
                except shodan.APIError as e:
                    if 'upgrade' in str(e).lower() or 'limit' in str(e).lower():
                        print(f"\n⚠️ API 限制: {e}")
                        print(f"   已獲取 {retrieved} 筆結果")
                        break
                    else:
                        raise e
            
            print(f"\n✅ 成功獲取 {len(all_matches)} 筆結果")
            
            # 處理結果
            results['matches'] = all_matches
            
            # 處理結果
            for result in results.get('matches', []):
                # 提取 hostnames
                hostnames = result.get('hostnames', [])
                ip = result.get('ip_str', '')
                port = result.get('port', '')
                
                for hostname in hostnames:
                    if hostname.endswith(f'.{domain}') or hostname == domain:
                        self.subdomains.add(hostname)
                        
                        # 記錄 IP 和端口
                        if ip:
                            self.subdomain_ips[hostname].add(ip)
                        if port:
                            self.subdomain_ports[hostname].add(port)
                
                # 從 SSL 憑證提取
                ssl_info = result.get('ssl', {})
                if ssl_info:
                    cert = ssl_info.get('cert', {})
                    
                    # 從 Subject CN 提取
                    subject = cert.get('subject', {})
                    cn = subject.get('CN', '')
                    if cn and (cn.endswith(f'.{domain}') or cn == domain):
                        # 處理萬用字元
                        if cn.startswith('*.'):
                            cn = cn[2:]  # 移除 *.
                        self.subdomains.add(cn)
                    
                    # 從 SAN 提取
                    extensions = cert.get('extensions', [])
                    for ext in extensions:
                        if isinstance(ext, dict) and ext.get('name') == 'subjectAltName':
                            san_data = ext.get('data', '')
                            # 解析 SAN
                            for match in re.findall(r'DNS:([^\s,]+)', san_data):
                                if match.endswith(f'.{domain}') or match == domain:
                                    if match.startswith('*.'):
                                        match = match[2:]
                                    self.subdomains.add(match)
            
            # 統計結果
            return self._analyze_results(domain)
            
        except shodan.APIError as e:
            print(f"❌ Shodan API 錯誤: {e}")
            return {}
        except Exception as e:
            print(f"❌ 錯誤: {e}")
            return {}
    
    def _analyze_results(self, domain: str) -> Dict:
        """分析並顯示結果"""
        print(f"\n{'='*60}")
        print(f"📊 統計結果")
        print(f"{'='*60}\n")
        
        # 基本統計
        total_subdomains = len(self.subdomains)
        print(f"✅ 找到 {total_subdomains} 個唯一子網域\n")
        
        if total_subdomains == 0:
            return {}
        
        # 顯示完整的 FQDN 清單
        print("📌 找到的完整網址清單 (FQDN):")
        print("-" * 40)
        sorted_subdomains = sorted(self.subdomains)
        
        # 詢問顯示方式
        if total_subdomains > 50:
            print(f"找到 {total_subdomains} 個子網域")
            show_option = input("顯示選項: (a)全部 (f)前50個 (l)後50個 (s)跳過: ").strip().lower()
            
            if show_option == 'a':
                for i, subdomain in enumerate(sorted_subdomains, 1):
                    # 顯示子網域和對應的 IP
                    ips = self.subdomain_ips.get(subdomain, set())
                    if ips:
                        print(f"{i:4d}. {subdomain:<50} -> {', '.join(ips)}")
                    else:
                        print(f"{i:4d}. {subdomain}")
            elif show_option == 'f':
                for i, subdomain in enumerate(sorted_subdomains[:50], 1):
                    ips = self.subdomain_ips.get(subdomain, set())
                    if ips:
                        print(f"{i:4d}. {subdomain:<50} -> {', '.join(ips)}")
                    else:
                        print(f"{i:4d}. {subdomain}")
                print(f"\n... 還有 {total_subdomains - 50} 個")
            elif show_option == 'l':
                start_num = total_subdomains - 49
                for i, subdomain in enumerate(sorted_subdomains[-50:], start_num):
                    ips = self.subdomain_ips.get(subdomain, set())
                    if ips:
                        print(f"{i:4d}. {subdomain:<50} -> {', '.join(ips)}")
                    else:
                        print(f"{i:4d}. {subdomain}")
        else:
            # 顯示全部（少於 50 個）
            for i, subdomain in enumerate(sorted_subdomains, 1):
                ips = self.subdomain_ips.get(subdomain, set())
                ports = self.subdomain_ports.get(subdomain, set())
                
                # 顯示子網域
                print(f"{i:4d}. {subdomain}")
                
                # 顯示 IP
                if ips:
                    print(f"       IP: {', '.join(sorted(ips))}")
                
                # 顯示端口
                if ports:
                    print(f"       端口: {', '.join(map(str, sorted(ports)))}")
        
        print("-" * 40)
        
        # 按層級分類子網域
        subdomain_levels = defaultdict(list)
        for subdomain in self.subdomains:
            # 計算子網域層級
            if subdomain == domain:
                level = 0  # 主域名
            else:
                # 移除主域名部分，計算剩餘的點數
                prefix = subdomain.replace(f'.{domain}', '')
                level = prefix.count('.') + 1
            
            subdomain_levels[level].append(subdomain)
        
        # 顯示各層級統計
        print("\n📌 按層級分類統計:")
        for level in sorted(subdomain_levels.keys()):
            count = len(subdomain_levels[level])
            if level == 0:
                print(f"   主域名: {count} 個")
            else:
                print(f"   {level} 級子域名: {count} 個")
        
        # 統計最多 IP 的子域名
        if self.subdomain_ips:
            print("\n📌 擁有最多 IP 的子域名:")
            sorted_by_ips = sorted(self.subdomain_ips.items(), 
                                  key=lambda x: len(x[1]), 
                                  reverse=True)[:5]
            for subdomain, ips in sorted_by_ips:
                print(f"   {subdomain}: {len(ips)} 個 IP")
                for ip in list(ips)[:3]:
                    print(f"      - {ip}")
                if len(ips) > 3:
                    print(f"      ... 還有 {len(ips) - 3} 個")
        
        # 統計最多端口的子域名
        if self.subdomain_ports:
            print("\n📌 開放最多端口的子域名:")
            sorted_by_ports = sorted(self.subdomain_ports.items(), 
                                    key=lambda x: len(x[1]), 
                                    reverse=True)[:5]
            for subdomain, ports in sorted_by_ports:
                print(f"   {subdomain}: {len(ports)} 個端口")
                port_list = sorted(list(ports))[:10]
                print(f"      端口: {', '.join(map(str, port_list))}")
                if len(ports) > 10:
                    print(f"      ... 還有 {len(ports) - 10} 個")
        
        # 返回統計結果
        return {
            'total_subdomains': total_subdomains,
            'subdomains': sorted_subdomains,
            'subdomain_levels': dict(subdomain_levels),
            'subdomain_ips': {k: list(v) for k, v in self.subdomain_ips.items()},
            'subdomain_ports': {k: list(v) for k, v in self.subdomain_ports.items()}
        }
    
    def export_results(self, domain: str, results: Dict):
        """匯出結果到檔案"""
        if not results:
            return
        
        print(f"\n{'='*60}")
        print("💾 匯出選項")
        print(f"{'='*60}")
        print("1. 匯出子域名清單 (純 FQDN)")
        print("2. 匯出詳細報告 (FQDN + IP + 端口)")
        print("3. 匯出 CSV 格式 (完整資訊)")
        print("4. 匯出可驗證清單 (FQDN + IP 對照)")
        print("5. 不匯出")
        
        choice = input("\n請選擇 (1-5): ").strip()
        
        if choice == "1":
            # 匯出簡單清單 (純 FQDN)
            filename = f"fqdn_list_{domain.replace('.', '_')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Shodan 搜尋結果 - {domain}\n")
                f.write(f"# 總計: {results['total_subdomains']} 個子網域\n")
                f.write(f"# 時間: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#" + "="*50 + "\n\n")
                
                for subdomain in results['subdomains']:
                    f.write(f"{subdomain}\n")
            print(f"✅ 已匯出 FQDN 清單到 {filename}")
            
        elif choice == "2":
            # 匯出詳細報告
            filename = f"fqdn_detailed_{domain.replace('.', '_')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Shodan 子網域掃描詳細報告\n")
                f.write(f"目標域名: {domain}\n")
                f.write(f"掃描時間: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                
                f.write(f"總計: {results['total_subdomains']} 個子網域\n\n")
                
                f.write("完整 FQDN 清單及詳細資訊:\n")
                f.write("-"*60 + "\n")
                
                for i, subdomain in enumerate(results['subdomains'], 1):
                    f.write(f"\n{i}. {subdomain}\n")
                    
                    # 寫入 IP 資訊
                    if subdomain in results['subdomain_ips']:
                        ips = results['subdomain_ips'][subdomain]
                        f.write(f"   IP 地址: {', '.join(ips)}\n")
                    
                    # 寫入端口資訊
                    if subdomain in results['subdomain_ports']:
                        ports = sorted(results['subdomain_ports'][subdomain])
                        f.write(f"   開放端口: {', '.join(map(str, ports))}\n")
            
            print(f"✅ 已匯出詳細報告到 {filename}")
            
        elif choice == "3":
            # 匯出 CSV (完整資訊)
            import csv
            filename = f"fqdn_complete_{domain.replace('.', '_')}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['編號', 'FQDN', 'IP地址', '端口', '層級'])
                
                for i, subdomain in enumerate(results['subdomains'], 1):
                    # 獲取 IP
                    ips = ', '.join(results.get('subdomain_ips', {}).get(subdomain, []))
                    
                    # 獲取端口
                    ports = ', '.join(map(str, sorted(results.get('subdomain_ports', {}).get(subdomain, []))))
                    
                    # 計算層級
                    if subdomain == domain:
                        level = "主域名"
                    else:
                        prefix = subdomain.replace(f'.{domain}', '')
                        level = f"{prefix.count('.') + 1}級"
                    
                    writer.writerow([i, subdomain, ips, ports, level])
            
            print(f"✅ 已匯出 CSV 到 {filename}")
            
        elif choice == "4":
            # 匯出可驗證清單 (FQDN + IP 對照)
            filename = f"fqdn_verify_{domain.replace('.', '_')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# FQDN 與 IP 對照表 - {domain}\n")
                f.write(f"# 可用於驗證 Shodan 結果是否正確\n")
                f.write(f"# 總計: {results['total_subdomains']} 個子網域\n")
                f.write("#" + "="*50 + "\n\n")
                
                # 先列出有 IP 的
                f.write("## 有 IP 記錄的子網域:\n")
                f.write("-"*50 + "\n")
                count_with_ip = 0
                for subdomain in results['subdomains']:
                    if subdomain in results.get('subdomain_ips', {}):
                        ips = results['subdomain_ips'][subdomain]
                        f.write(f"{subdomain:<50} -> {', '.join(ips)}\n")
                        count_with_ip += 1
                
                # 再列出沒有 IP 的
                f.write(f"\n## 沒有 IP 記錄的子網域 ({results['total_subdomains'] - count_with_ip} 個):\n")
                f.write("-"*50 + "\n")
                for subdomain in results['subdomains']:
                    if subdomain not in results.get('subdomain_ips', {}):
                        f.write(f"{subdomain}\n")
                
                f.write(f"\n## 統計:\n")
                f.write(f"- 有 IP 記錄: {count_with_ip} 個\n")
                f.write(f"- 無 IP 記錄: {results['total_subdomains'] - count_with_ip} 個\n")
                f.write(f"- 總計: {results['total_subdomains']} 個\n")
            
            print(f"✅ 已匯出可驗證清單到 {filename}")

def main():
    """主程式"""
    print("🔍 Shodan 子網域統計工具")
    print("="*60)
    
    # API Key 設定
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")  # 請替換成你的 API Key
    
    if SHODAN_API_KEY == "your_shodan_api_key_here":
        print("❌ 請設定 Shodan API Key")
        api_key = input("請輸入 Shodan API Key: ").strip()
        if not api_key:
            print("❌ API Key 不能為空")
            return
        SHODAN_API_KEY = api_key
    
    # 建立掃描器
    scanner = ShodanSubdomainCounter(SHODAN_API_KEY)
    
    # 顯示 API 資訊
    try:
        api_info = scanner.api.info()
        print(f"\n📊 API 帳號資訊:")
        print(f"   計畫類型: {api_info.get('plan', 'Unknown')}")
        print(f"   查詢點數: {api_info.get('query_credits', 0)}")
        print(f"   掃描點數: {api_info.get('scan_credits', 0)}")
    except:
        print("⚠️ 無法獲取 API 資訊")
    
    while True:
        print("\n" + "="*60)
        print("選項:")
        print("1. 標準查詢（最多 100 筆）")
        print("2. 嘗試獲取全部結果")
        print("3. 使用多種技巧獲取更多結果")
        print("4. 結合 SSL 憑證搜尋")
        print("5. 離開")
        
        choice = input("\n請選擇 (1-5): ").strip()
        
        if choice == "5":
            print("👋 再見！")
            break
        
        if choice in ["1", "2"]:
            # 輸入域名
            domain = input("\n請輸入要查詢的域名 (例如: tn.edu.tw): ").strip()
            
            if not domain:
                print("❌ 請輸入有效的域名")
                continue
            
            # 清理域名
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            if '/' in domain:
                domain = domain.split('/')[0]
            
            # 重置之前的結果
            scanner.subdomains = set()
            scanner.subdomain_ips = defaultdict(set)
            scanner.subdomain_ports = defaultdict(set)
            
            # 執行查詢
            if choice == "1":
                results = scanner.search_domain(domain, get_all=False)
            else:
                results = scanner.search_domain(domain, get_all=True)
            
            # 詢問是否匯出
            if results:
                scanner.export_results(domain, results)
        
        elif choice == "3":
            # 使用多種技巧
            domain = input("\n請輸入要查詢的域名 (例如: tn.edu.tw): ").strip()
            
            if not domain:
                print("❌ 請輸入有效的域名")
                continue
            
            # 清理域名
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            if '/' in domain:
                domain = domain.split('/')[0]
            
            print("\n🔍 使用多種查詢技巧...")
            
            # 重置結果
            scanner.subdomains = set()
            scanner.subdomain_ips = defaultdict(set)
            scanner.subdomain_ports = defaultdict(set)
            
            # 技巧 1: 基本 hostname 搜尋
            print("\n📌 技巧 1: Hostname 搜尋")
            scanner.search_domain(domain, get_all=False)
            count1 = len(scanner.subdomains)
            print(f"   累計找到: {count1} 個子域名")
            
            # 技巧 2: SSL 憑證搜尋
            print("\n📌 技巧 2: SSL 憑證搜尋")
            query = f'ssl.cert.subject.cn:"*.{domain}" OR ssl.cert.subject.cn:"{domain}"'
            try:
                results = scanner.api.search(query, limit=100)
                for result in results.get('matches', []):
                    hostnames = result.get('hostnames', [])
                    for hostname in hostnames:
                        if hostname.endswith(f'.{domain}') or hostname == domain:
                            scanner.subdomains.add(hostname)
            except:
                pass
            count2 = len(scanner.subdomains)
            print(f"   累計找到: {count2} 個子域名 (+{count2-count1})")
            
            # 技巧 3: 搜尋特定端口
            print("\n📌 技巧 3: 搜尋常見端口")
            ports = [80, 443, 8080, 8443, 21, 22, 25]
            for port in ports:
                query = f'hostname:".{domain}" port:{port}'
                try:
                    results = scanner.api.search(query, limit=50)
                    for result in results.get('matches', []):
                        hostnames = result.get('hostnames', [])
                        for hostname in hostnames:
                            if hostname.endswith(f'.{domain}') or hostname == domain:
                                scanner.subdomains.add(hostname)
                except:
                    pass
                time.sleep(1)
            count3 = len(scanner.subdomains)
            print(f"   累計找到: {count3} 個子域名 (+{count3-count2})")
            
            # 顯示最終結果
            results = scanner._analyze_results(domain)
            if results:
                scanner.export_results(domain, results)
        
        elif choice == "4":
            # SSL 憑證專門搜尋
            domain = input("\n請輸入要查詢的域名 (例如: tn.edu.tw): ").strip()
            
            if not domain:
                print("❌ 請輸入有效的域名")
                continue
            
            # 清理域名
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            if '/' in domain:
                domain = domain.split('/')[0]
            
            print("\n🔍 SSL 憑證深度搜尋...")
            
            # 重置結果
            scanner.subdomains = set()
            scanner.subdomain_ips = defaultdict(set)
            scanner.subdomain_ports = defaultdict(set)
            
            # 多種 SSL 查詢
            queries = [
                f'ssl.cert.subject.cn:"*.{domain}"',
                f'ssl.cert.subject.cn:"{domain}"',
                f'ssl:"*.{domain}"',
                f'ssl:"{domain}"',
                f'ssl.cert.subject.organization:"{domain.split(".")[0]}"'
            ]
            
            for i, query in enumerate(queries, 1):
                print(f"\n查詢 {i}/{len(queries)}: {query}")
                try:
                    results = scanner.api.search(query, limit=100)
                    for result in results.get('matches', []):
                        # 從 hostnames 提取
                        hostnames = result.get('hostnames', [])
                        for hostname in hostnames:
                            if hostname.endswith(f'.{domain}') or hostname == domain:
                                scanner.subdomains.add(hostname)
                                
                                # 記錄 IP 和端口
                                ip = result.get('ip_str', '')
                                port = result.get('port', '')
                                if ip:
                                    scanner.subdomain_ips[hostname].add(ip)
                                if port:
                                    scanner.subdomain_ports[hostname].add(port)
                        
                        # 從 SSL 憑證提取
                        ssl_info = result.get('ssl', {})
                        if ssl_info:
                            cert = ssl_info.get('cert', {})
                            
                            # Subject CN
                            subject = cert.get('subject', {})
                            cn = subject.get('CN', '')
                            if cn:
                                if cn.startswith('*.'):
                                    cn = cn[2:]
                                if cn.endswith(f'.{domain}') or cn == domain:
                                    scanner.subdomains.add(cn)
                            
                            # SAN
                            extensions = cert.get('extensions', [])
                            for ext in extensions:
                                if isinstance(ext, dict) and ext.get('name') == 'subjectAltName':
                                    san_data = ext.get('data', '')
                                    import re
                                    for match in re.findall(r'DNS:([^\s,]+)', san_data):
                                        if match.startswith('*.'):
                                            match = match[2:]
                                        if match.endswith(f'.{domain}') or match == domain:
                                            scanner.subdomains.add(match)
                    
                    print(f"   目前累計: {len(scanner.subdomains)} 個子域名")
                    time.sleep(1)
                    
                except shodan.APIError as e:
                    print(f"   錯誤: {e}")
                except Exception as e:
                    print(f"   錯誤: {e}")
            
            # 顯示最終結果
            results = scanner._analyze_results(domain)
            if results:
                scanner.export_results(domain, results)

if __name__ == "__main__":
    main()