"""
主程式入口
"""
import time
from typing import List, Optional
import argparse
import sys
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config
import dns.resolver
import dns.exception
from database.repository import DatabaseManagerORM as DatabaseManager
from scanners.shodan_scanner import ShodanScanner, fetch_shodan_http_batch
from scanners.shodan_fqdn import ShodanFqdnScanner
from scanners.virustotal_scanner import VirusTotalScanner
from scanners.crtsh_scanner import CrtshScanner
from scanners.dns_zone_scanner import DnsZoneScanner
from validators.otx_validator import OtxValidator
from validators.certificate_validator import CertificateValidator
from models.website import Website
from utils.network import rate_limit
from utils.logger import get_logger
from domain_hierarchy import build_domain_hierarchy

logger = get_logger("main")

class WebsiteFinder:
    """網站發現主程式"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db_manager = DatabaseManager(config.DATABASE_PATH)
        self.shodan_scanner = ShodanScanner(config.SHODAN_API_KEY, self.db_manager)
        self.shodan_fqdn_scanner = ShodanFqdnScanner(config.SHODAN_API_KEY)
        self.crtsh_scanner = CrtshScanner()
        self.dns_zone_scanner = DnsZoneScanner(config)
        # VirusTotal 支援多組 key：直接傳整個列表（或單一）
        self.vt_scanner = VirusTotalScanner(config.VIRUSTOTAL_API_KEYS)
        self.validator = OtxValidator(config)
        self.certificate_validator = CertificateValidator()
    
    def run(self, cert_pattern: str, quick_mode: bool = False, skip_xlsx: bool = False) -> List[Website]:
        """執行完整的搜尋流程
        
        Args:
            cert_pattern: 憑證搜尋模式
            quick_mode: 快速模式，限制查詢範圍
            skip_xlsx: 跳過 xlsx 匯入，只使用 Shodan 結果
        """
        logger.info("="*60)
        logger.info(f"開始搜尋憑證: {cert_pattern}")
        if skip_xlsx:
            logger.info("模式: 只查詢 Shodan 結果（跳過 xlsx）")
        else:
            logger.info("模式: Shodan + xlsx 合併查詢")
        logger.info("="*60)
        
        # 步驟 1: Shodan 搜尋
        logger.info("步驟 1: Shodan 搜尋")
        shodan_result = self.shodan_scanner.scan(
            cert_pattern,
            country=self.config.DEFAULT_COUNTRY,
            port=self.config.DEFAULT_PORT
        )
        
        if not shodan_result.domains:
            logger.warning("Shodan 沒有找到相關域名")
        else:
            logger.info(f"Shodan 找到 {len(shodan_result.domains)} 個域名")
        
        # 取得 Shodan 的 VT 目標
        shodan_vt_targets = shodan_result.vt_query_targets if shodan_result.vt_query_targets else shodan_result.domains
        shodan_vt_set = set(shodan_vt_targets) if shodan_vt_targets else set()
        
        # 步驟 1.5: 匯入 xlsx 的 root_domain 並合併（可跳過）
        if skip_xlsx:
            logger.info("步驟 1.5: 跳過 xlsx 匯入（模式 2）")
            vt_targets = list(shodan_vt_targets or [])
            logger.info(f"VT 查詢目標：只有 Shodan {len(vt_targets)} 個")
        else:
            logger.info("步驟 1.5: 匯入 xlsx root_domain 並合併 Shodan 結果")
            xlsx_imported = self.db_manager.import_root_domains_from_xlsx("institution")
            logger.info(f"xlsx 匯入了 {xlsx_imported} 個新的 root_domain")
            
            # 取得 xlsx 的 root_domain（source='xlsx'）
            xlsx_root_domains = self.db_manager.get_all_root_domains(source="xlsx")
            
            # 合併：Shodan 優先，xlsx 補充（去除已存在於 Shodan 結果的）
            xlsx_only = [rd for rd in xlsx_root_domains if rd not in shodan_vt_set]
            vt_targets = list(shodan_vt_targets or []) + xlsx_only
            
            logger.info(f"合併後 VT 查詢目標：Shodan {len(shodan_vt_set)} 個 + xlsx 補充 {len(xlsx_only)} 個 = 共 {len(vt_targets)} 個")
        
        if not vt_targets:
            logger.warning("沒有任何 VT 查詢目標（Shodan + xlsx 皆為空）")
            return []
        
        # 步驟 2 + 3 改為「逐個 VT 目標域名即時處理」：
        #   1) 取該 root domain 的 subdomains
        #   2) 預先寫入（DNS 預解析）
        #   3) 立即執行 OTX 驗證並更新該批
        logger.info("步驟 2: VirusTotal 獲得subdomains並即時 OTX 驗證")
        
        # 快速模式：限制查詢目標
        if quick_mode:
            vt_targets = vt_targets[:1]  # 只處理第一個域名
            logger.info(f"🚀 快速模式：限制為 {len(vt_targets)} 個目標")
        
        logger.info(f"共有 {len(vt_targets)} 個 VT 查詢目標 (VT Keys: {len(self.config.VIRUSTOTAL_API_KEYS)})，將逐一處理")

        processed_subdomains: set[str] = set()  # 避免跨 root 重複處理
        aggregated_validated: List[Website] = []
        
        # 取得 area domains 用於 Shodan FQDN 判斷
        area_domains = self.db_manager.get_all_area_domains()
        searched_area_domains: set[str] = set()  # 記錄已查過 Shodan FQDN 的 area domain
        logger.info(f"載入 {len(area_domains)} 個 area domain 用於 Shodan FQDN 判斷") 

        def _resolve_ips(domain: str) -> tuple[List[str], List[str], int | None, int | None, int | None, List[str]]:
            """解析 A / AAAA / CNAME，回傳 IP 與第一跳 CNAME target。"""
            ipv4_list: List[str] = []
            ipv6_list: List[str] = []
            has_a: int | None = None
            has_aaaa: int | None = None
            has_cname: int | None = None
            cname_targets: List[str] = []
            # 建立專用 Resolver 並設定 nameservers
            try:
                resolver = dns.resolver.Resolver()
                # 過濾空字串，避免 [''] 導致錯誤
                ns = [s.strip() for s in (self.config.DNS_SERVERS or []) if s and s.strip()]
                if ns:
                    resolver.nameservers = ns
            except Exception as e:
                logger.debug(f"建立 DNS Resolver 失敗，使用預設解析器：{e}")
                resolver = dns.resolver.Resolver()
            try:
                ans4 = resolver.resolve(domain, 'A', lifetime=3.0)
                if ans4:
                    ipv4_list = [rr.to_text() for rr in ans4]
                    has_a = 1
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
                logger.debug(f"DNS A 預解析失敗 {domain}: {e}")
            except Exception as e:
                logger.debug(f"DNS A 預解析未預期錯誤 {domain}: {e}")
            try:
                ans6 = resolver.resolve(domain, 'AAAA', lifetime=3.0)
                if ans6:
                    ipv6_list = [rr.to_text() for rr in ans6]
                    has_aaaa = 1
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
                logger.debug(f"DNS AAAA 預解析失敗 {domain}: {e}")
            except Exception as e:
                logger.debug(f"DNS AAAA 預解析未預期錯誤 {domain}: {e}")
            try:
                ans_cname = resolver.resolve(domain, 'CNAME', lifetime=3.0)
                if ans_cname:
                    has_cname = 1
                    cname_targets = [str(rr.target).rstrip(".").lower() for rr in ans_cname if getattr(rr, "target", None)]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
                logger.debug(f"DNS CNAME 預解析失敗 {domain}: {e}")
            except Exception as e:
                logger.debug(f"DNS CNAME 預解析未預期錯誤 {domain}: {e}")
            return ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets

        from models.website import Website as _W

        def _extract_root_domain(domain: str) -> str:
            """從域名提取 root domain（最後兩段或三段 .edu.tw）"""
            parts = domain.lower().split('.')
            if len(parts) >= 3 and parts[-2] == 'edu' and parts[-1] == 'tw':
                # xxx.edu.tw 格式
                return '.'.join(parts[-3:])
            elif len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain

        for idx, target in enumerate(vt_targets, start=1):
            logger.info("-" * 50)
            logger.info(f"[VT+Shodan DNS] ({idx}/{len(vt_targets)}) 處理 root domain: {target}")
            
            # 1. Shodan DNS API 查詢邏輯：
            #    - 如果 target 的 root domain 是 area → 只查一次該 area domain
            #    - 如果不是 area → 正常查 target
            shodan_results = []
            shodan_subdomains = []
            root_of_target = _extract_root_domain(target)
            
            if root_of_target in area_domains:
                # target 屬於 area（例如 ytes.ntpc.edu.tw，root = ntpc.edu.tw）
                if root_of_target not in searched_area_domains:
                    # 這個 area 還沒查過 → 查 area domain
                    logger.info(f"[Shodan DNS] {target} 屬於 area {root_of_target}，查詢 area domain")
                    shodan_results = self.shodan_fqdn_scanner.get_subdomains_with_a_record(root_of_target)
                    shodan_subdomains = [result["fqdn"] for result in shodan_results]
                    searched_area_domains.add(root_of_target)
                    logger.info(f"[Shodan DNS] area {root_of_target} 取得 {len(shodan_subdomains)} 個子網域（已記錄，後續同 area 不再查）")
                else:
                    # 這個 area 已經查過 → 跳過 Shodan FQDN
                    logger.info(f"[Shodan DNS] {target} 屬於已查過的 area {root_of_target}，跳過 Shodan FQDN")
            else:
                # 不是 area → 正常查詢
                shodan_results = self.shodan_fqdn_scanner.get_subdomains_with_a_record(target)
                shodan_subdomains = [result["fqdn"] for result in shodan_results]
                logger.info(f"[Shodan DNS] {target} 取得 {len(shodan_subdomains)} 個 A/AAAA/CNAME record 子網域")
            
            # 2. 再用 VT 取得子網域
            vt_subdomains = self._get_subdomains_with_delay(target)
            logger.info(f"[VT] {target} 取得 {len(vt_subdomains)} 個子網域")

            # 3. 再用 crt.sh 取得子網域（name_value）
            crt_subdomains = self.crtsh_scanner.get_subdomains(target)
            logger.info(f"[crt.sh] {target} 取得 {len(crt_subdomains)} 個子網域")
            
            # 4. 合併去重：VT + Shodan + crt.sh，相同的只保留一個
            all_subs_set = set(vt_subdomains)  # 先放 VT 的
            all_subs_set.update(shodan_subdomains)  # 再加 Shodan 的（自動去重）
            all_subs_set.update(crt_subdomains)  # 再加 crt.sh（自動去重）
            all_subdomains = list(all_subs_set)
            
            overlap_vt_shodan = len(set(shodan_subdomains) & set(vt_subdomains))
            overlap_vt_crt = len(set(vt_subdomains) & set(crt_subdomains))
            overlap_shodan_crt = len(set(shodan_subdomains) & set(crt_subdomains))
            logger.info(
                f"[合併] {target} 合併後共 {len(all_subdomains)} 個子網域 "
                f"（VT+Shodan 重疊 {overlap_vt_shodan}、VT+crt.sh 重疊 {overlap_vt_crt}、Shodan+crt.sh 重疊 {overlap_shodan_crt}）"
            )
            
            if not all_subdomains:
                logger.warning(f"[合併] {target} 無子域名，跳過")
                continue

            # 去掉已處理過的重複子域名
            new_subs = [s for s in all_subdomains if s not in processed_subdomains]
            skipped = len(all_subdomains) - len(new_subs)
            if skipped:
                logger.info(f"[合併] {target} 略過 {skipped} 個已處理過的重複子域名")
            if not new_subs:
                continue

            # 預先寫入（未驗證 when_latest_otx_checked=None）
            # 現在所有 IP 都由 DNS 預解析取得（Shodan 只提供 FQDN 清單）
            # 使用多執行緒並行 DNS 解析
            dns_results: dict[str, tuple[List[str], List[str], int | None, int | None, int | None, List[str]]] = {}
            dns_workers = min(20, len(new_subs))  # 最多 20 個執行緒
            
            logger.info(f"[DNS] 開始並行解析 {len(new_subs)} 個子網域（執行緒數: {dns_workers}）")
            with ThreadPoolExecutor(max_workers=dns_workers) as executor:
                future_to_sub = {executor.submit(_resolve_ips, sub): sub for sub in new_subs}
                for future in as_completed(future_to_sub):
                    sub = future_to_sub[future]
                    try:
                        ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets = future.result()
                        dns_results[sub] = (ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets)
                    except Exception as e:
                        logger.debug(f"[DNS] 解析 {sub} 失敗: {e}")
                        dns_results[sub] = ([], [], None, None, None, [])
            
            prelist: List[_W] = []
            unresolved = 0
            for sub in new_subs:
                ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets = dns_results.get(sub, ([], [], None, None, None, []))
                if not (ipv4_list or ipv6_list):
                    unresolved += 1
                # Website 不再需要傳入 ip 參數，改用 ipv4_list/ipv6_list 屬性
                w = _W(fqdn=sub, url=f"http://{sub}")
                # 將雙協定結果附加為屬性（列表形式）
                setattr(w, "ipv4_list", ipv4_list)
                setattr(w, "ipv6_list", ipv6_list)
                # DNS 紀錄存在旗標
                setattr(w, "has_a", has_a)
                setattr(w, "has_aaaa", has_aaaa)
                setattr(w, "has_cname", has_cname)
                setattr(w, "cname_targets", cname_targets)
                prelist.append(w)

            # 步驟 2.5: 域名階層分解（在 OTX 驗證前）
            logger.info(f"[域名階層] 開始分解 {target} 的域名階層")
            try:
                # 使用此目標作為根域名，對所有子域名進行階層分解
                domain_id_map = build_domain_hierarchy(
                    db_manager=self.db_manager,
                    all_fqdns=all_subdomains,  # 所有找到的子域名
                    root_domains=[target]  # 根域名清單
                )
                logger.info(f"[域名階層] {target} 建立了 {len(domain_id_map)} 個域名階層關係")
            except Exception as e:
                logger.error(f"[域名階層] {target} 域名階層分解失敗： {e}")
                # 繼續後續步驟，但可能會有問題

            pre_saved = self.db_manager.save_websites_batch(prelist, root_domain_name=target, when_latest_otx_checked=None)
            logger.info(f"[DB] {target} 預先寫入 {pre_saved} 筆 (未驗證 when_latest_otx_checked=None)，DNS 未解析 {unresolved} 筆")

            # 步驟 2.6: DNS Zone (SOA/NS) 掃描並入庫
            logger.info(f"[DNS Zone] 掃描 {target} 的 {len(new_subs)} 個子網域 SOA/NS")
            try:
                zone_info = self.dns_zone_scanner.get_zone_info_batch(new_subs)
                zones_saved, links_saved = self.db_manager.save_dns_zone_batch(zone_info)
                logger.info(f"[DNS Zone] {target} 儲存 zone {zones_saved} 筆、domain-zone 關聯 {links_saved} 筆")
            except Exception as e:
                logger.error(f"[DNS Zone] {target} 掃描或儲存失敗: {e}")

            # 立即 OTX 驗證這批新子域名
            logger.info(f"[OTX] 驗證 {target} 的 {len(new_subs)} 個子域名")
            validated = self.validator.validate_websites(new_subs)
            if not validated:
                logger.warning(f"[OTX] {target} 無成功驗證子域名")
                processed_subdomains.update(new_subs)
                continue

            # 寫回驗證成功 (覆寫 IP 差異 + when_latest_otx_checked=當前時間)
            updated = 0
            current_time = datetime.now()
            for site in validated:
                try:
                    existing = self.db_manager.get_website_by_fqdn(site.fqdn)
                except Exception:
                    existing = None
                # 不再根據 OTX 覆寫或提示 IP 差異（OTX 僅作存在性驗證）
                # 若 OTX 回傳未帶出 v4/v6，盡量沿用預存紀錄的雙協定資訊
                if not hasattr(site, "ipv4") and existing and hasattr(existing, "ipv4"):
                    setattr(site, "ipv4", getattr(existing, "ipv4", None))
                if not hasattr(site, "ipv6") and existing and hasattr(existing, "ipv6"):
                    setattr(site, "ipv6", getattr(existing, "ipv6", None))
                if self.db_manager.save_website(site, root_domain_name=target, when_latest_otx_checked=current_time):
                    updated += 1
            logger.info(f"[DB] {target} 更新驗證成功 {updated} 筆 (when_latest_otx_checked={current_time.strftime('%Y-%m-%d %H:%M:%S')})")

            # 步驟 3.5: 取得並儲存 OTX HTTP Scans 資料
            validated_fqdns = [site.fqdn for site in validated]
            logger.info(f"[OTX HTTP Scans] 取得 {target} 的 {len(validated_fqdns)} 個已驗證域名的 http_scans")
            try:
                http_scans_dict = self.validator.fetch_http_scans_batch(validated_fqdns)
                if http_scans_dict:
                    saved_count = self.db_manager.save_http_scans_batch(http_scans_dict)
                    logger.info(f"[DB] {target} 儲存 {saved_count} 筆 http_scans 資料")
                else:
                    logger.info(f"[OTX HTTP Scans] {target} 無 http_scans 資料")
            except Exception as e:
                logger.error(f"[OTX HTTP Scans] 取得或儲存 {target} 的 http_scans 失敗: {e}")

            # 步驟 3.6: Shodan HTTP 查詢與 IoT 標記
            logger.info(f"[Shodan HTTP] 查詢 {target} 的 {len(validated_fqdns)} 個 subdomain")
            try:
                known_ips_by_subdomain: dict[str, set[str]] = {}
                for fqdn in validated_fqdns:
                    try:
                        website = self.db_manager.get_website_by_fqdn(fqdn)
                    except Exception:
                        website = None
                    if not website:
                        continue

                    known_ips: set[str] = set()
                    known_ips.update(getattr(website, "ipv4_list", []) or [])
                    known_ips.update(getattr(website, "ipv6_list", []) or [])
                    if getattr(website, "ipv4", None):
                        known_ips.add(website.ipv4)
                    if getattr(website, "ipv6", None):
                        known_ips.add(website.ipv6)
                    if known_ips:
                        known_ips_by_subdomain[fqdn] = known_ips

                html_data, product_data = fetch_shodan_http_batch(
                    api_key=self.config.SHODAN_API_KEY,
                    subdomains=validated_fqdns,
                    delay=1.0,
                    known_ips_by_subdomain=known_ips_by_subdomain,
                )
                if html_data:
                    saved = self.db_manager.save_shodan_http_batch(html_data)
                    logger.info(f"[Shodan HTTP] {target} 儲存 {saved} 筆 http.html 資料")
                else:
                    logger.info(f"[Shodan HTTP] {target} 無 http.html 資料")
                
                if product_data:
                    saved_products = self.db_manager.save_shodan_product_batch(product_data)
                    logger.info(f"[Shodan Product] {target} 儲存 {saved_products} 筆 product 資料")
                else:
                    logger.info(f"[Shodan Product] {target} 無 product 資料")
            except Exception as e:
                logger.error(f"[Shodan HTTP] {target} 查詢失敗: {e}")

            aggregated_validated.extend(validated)
            processed_subdomains.update(new_subs)

        if not aggregated_validated:
            logger.warning("整體流程結束：沒有任何子域名通過 OTX 驗證")
            return []

        # 步驟 4: 憑證驗證（在 OTX 驗證後執行）
        logger.info("\n步驟 4: 憑證驗證")
        logger.info("-" * 50)
        try:
            checked, updated = self.certificate_validator.validate_all_domains()
            logger.info(f"憑證驗證完成：檢查了 {checked} 個主機，更新了 {updated} 個憑證檢查時間")
        except Exception as e:
            logger.error(f"憑證驗證過程發生錯誤： {e}")
            logger.warning("憑證驗證失敗，但不影響主流程繼續執行")

        # 最終統計顯示
        self._display_statistics(aggregated_validated)
        return aggregated_validated
    
    @rate_limit(2.0)  # VirusTotal API 速率限制（外部再做一層保守限制）
    def _get_subdomains_with_delay(self, domain: str) -> List[str]:
        """帶延遲的子域名查詢"""
        return self.vt_scanner.get_subdomains(domain)
    
    def _display_statistics(self, websites: List[Website]) -> None:
        """顯示統計資訊"""
        logger.info("="*60)
        logger.info("搜尋結果統計")
        logger.info("="*60)
        
        if websites:
            logger.info(f"找到 {len(websites)} 個可連線的網站:")
            for i, site in enumerate(websites, 1):
                logger.info(f"{i:2d}. {site.url}")
                if site.redirect_to:
                    logger.info(f"    重定向到: {site.redirect_to}")
        
        # 資料庫統計
        total_count, unique_ips = self.db_manager.get_statistics()
        logger.info(f"資料庫統計:")
        logger.info(f"  總域名數: {total_count}")
        logger.info(f"  獨特 IP 數: {unique_ips}")

def main():
    """主函數"""
    parser = argparse.ArgumentParser(
        description='Shodan + VirusTotal 網站發現工具'
    )
    parser.add_argument(
        'cert_pattern',
        nargs='?',
        help='憑證模式 (例如: *.ptivs.tn.edu.tw)'
    )
    parser.add_argument(
        '--shodan-key',
        help='Shodan API Key',
        default=None
    )
    parser.add_argument(
        '--vt-key',
        help='VirusTotal API Key (單一 key 或逗號分隔多 key)',
        default=None
    )
    parser.add_argument(
        '--db-path',
        help='資料庫路徑',
        default='website.db'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='快速模式：限制查詢數量進行測試'
    )
    
    args = parser.parse_args()
    
    # 建立配置
    config = Config.from_env()
    
    # 覆寫 API Keys（如果有提供）
    if args.shodan_key:
        config.SHODAN_API_KEY = args.shodan_key.strip()
    if args.vt_key:
        # 允許多組 key 以逗號輸入
        from config import _parse_vt_multi  # 重用解析
        config.VIRUSTOTAL_API_KEYS = _parse_vt_multi(args.vt_key)
    if args.db_path:
        config.DATABASE_PATH = args.db_path
    
    # 驗證配置
    try:
        config.validate()
    except ValueError as e:
        logger.error(f"配置錯誤: {e}")
        logger.info("請設定環境變數或使用命令列參數提供 API Keys")
        sys.exit(1)
    
    # 取得憑證模式
    if not args.cert_pattern:
        print("請輸入要搜尋的憑證模式 (例如: *.ptivs.tn.edu.tw)")
        cert_pattern = input("憑證模式: ").strip()
        if not cert_pattern:
            logger.error("請輸入有效的憑證模式")
            sys.exit(1)
    else:
        cert_pattern = args.cert_pattern
    
    # 選擇查詢模式
    print("\n請選擇查詢模式:")
    print("  1. Shodan + xlsx 合併查詢（完整模式）")
    print("  2. 只查詢 Shodan 結果（跳過 xlsx）")
    mode_input = input("請輸入模式 (1 或 2，預設 1): ").strip()
    skip_xlsx = (mode_input == "2")
    
    # 執行搜尋
    try:
        finder = WebsiteFinder(config)
        if args.quick:
            logger.info("快速模式啟用：將限制查詢範圍進行測試")
        results = finder.run(cert_pattern, quick_mode=args.quick, skip_xlsx=skip_xlsx)
        
        if results:
            logger.info(f"\n搜尋完成！找到 {len(results)} 個網站")
        else:
            logger.info("\n搜尋完成，但沒有找到可用的網站")
            
    except KeyboardInterrupt:
        print("\n\n程式已被使用者中斷")
        logger.info("使用者中斷程式")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程式執行錯誤: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
