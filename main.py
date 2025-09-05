"""
主程式入口
"""
import time
from typing import List
import argparse
import sys
from pathlib import Path

# 加入專案路徑
#sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from database.repository import DatabaseManagerORM as DatabaseManager
from scanners.shodan_scanner import ShodanScanner
from scanners.virustotal_scanner import VirusTotalScanner
from validators.website_validator import WebsiteValidator
from models.website import Website
from utils.network import rate_limit
from utils.logger import get_logger

logger = get_logger("main")

class WebsiteFinder:
    """網站發現主程式"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db_manager = DatabaseManager(config.DATABASE_PATH)
        self.shodan_scanner = ShodanScanner(config.SHODAN_API_KEY, self.db_manager)
        self.vt_scanner = VirusTotalScanner(config.VIRUSTOTAL_API_KEY)
        self.validator = WebsiteValidator(config)
    
    def run(self, cert_pattern: str) -> List[Website]:
        """執行完整的搜尋流程"""
        logger.info("="*60)
        logger.info(f"開始搜尋憑證: {cert_pattern}")
        logger.info("="*60)
        
        # 步驟 1: Shodan 搜尋
        logger.info("步驟 1: Shodan 搜尋")
        shodan_result = self.shodan_scanner.scan(
            cert_pattern,
            country=self.config.DEFAULT_COUNTRY,
            port=self.config.DEFAULT_PORT
        )
        
        if not shodan_result.domains:
            logger.warning("沒有找到相關域名")
            return []
        
        logger.info(f"找到 {len(shodan_result.domains)} 個域名")
        
        # 步驟 2: VirusTotal 查詢子域名
        logger.info("步驟 2: VirusTotal 查詢子域名")
        all_subdomains = set()
        
        # 使用處理過的 VT 查詢目標（已比對 institution.domain）
        vt_targets = shodan_result.vt_query_targets if shodan_result.vt_query_targets else shodan_result.domains
        logger.info(f"使用 {len(vt_targets)} 個 VT 查詢目標")
        
        for target in vt_targets:
            subdomains = self._get_subdomains_with_delay(target)
            all_subdomains.update(subdomains)
        
        if not all_subdomains:
            logger.warning("沒有找到子域名")
            return []
        
        unique_subdomains = sorted(list(all_subdomains))
        logger.info(f"總計找到 {len(unique_subdomains)} 個獨特的子域名")
        
        # 步驟 3: 驗證網站連線性
        logger.info("步驟 3: 驗證網站連線性")
        working_websites = self.validator.validate_websites(unique_subdomains)
        
        # 步驟 4: 儲存到資料庫
        logger.info("步驟 4: 儲存到資料庫")
        # 使用 VirusTotal 查詢目標作為 root domain
        root_domain = vt_targets[0] if vt_targets else cert_pattern
        saved_count = self.db_manager.save_websites_batch(working_websites, root_domain_name=root_domain)
        logger.info(f"成功儲存 {saved_count} 筆記錄，root_domain: {root_domain}")
        
        # 顯示統計
        self._display_statistics(working_websites)
        
        return working_websites
    
    @rate_limit(2.0)  # VirusTotal API 速率限制
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
                logger.info(f"{i:2d}. {site.url} -> {site.ip}")
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
        help='VirusTotal API Key',
        default=None
    )
    parser.add_argument(
        '--db-path',
        help='資料庫路徑',
        default='website.db'
    )
    
    args = parser.parse_args()
    
    # 建立配置
    config = Config.from_env()
    
    # 覆寫 API Keys（如果有提供）
    if args.shodan_key:
        config.SHODAN_API_KEY = args.shodan_key
    if args.vt_key:
        config.VIRUSTOTAL_API_KEY = args.vt_key
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
    
    # 執行搜尋
    try:
        finder = WebsiteFinder(config)
        results = finder.run(cert_pattern)
        
        if results:
            logger.info(f"\n搜尋完成！找到 {len(results)} 個網站")
        else:
            logger.info("\n搜尋完成，但沒有找到可用的網站")
            
    except KeyboardInterrupt:
        logger.info("\n使用者中斷程式")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程式執行錯誤: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()