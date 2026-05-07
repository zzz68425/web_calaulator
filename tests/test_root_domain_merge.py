"""
測試程式：模擬專案流程（步驟 1 ~ 步驟 2 之前）
- 建立測試資料庫
- 步驟 1: Shodan 搜尋
- 步驟 1.5: 匯入 xlsx root_domain 並合併
- 輸出最終的 VirusTotal 查詢列表
"""
import os
from datetime import datetime
from config import Config
from database.repository import DatabaseManagerORM
from scanners.shodan_scanner import ShodanScanner
from utils.logger import get_logger

logger = get_logger("test_merge")

# 測試用資料庫路徑
TEST_DB_PATH = "test_merge_db.db"

def test_root_domain_merge():
    """模擬專案流程：步驟 1 ~ 步驟 2 之前"""
    
    config = Config()
    
    # 刪除舊的測試資料庫（如果存在）
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
        print(f"已刪除舊的測試資料庫: {TEST_DB_PATH}")
    
    # 建立新的測試資料庫
    print(f"建立測試資料庫: {TEST_DB_PATH}")
    db_manager = DatabaseManagerORM(TEST_DB_PATH)
    
    print("=" * 60)
    print("模擬專案流程：步驟 1 ~ 步驟 2 之前")
    print("=" * 60)
    
    # ========== 步驟 1: Shodan 搜尋 ==========
    print("\n【步驟 1】Shodan 搜尋")
    print("-" * 40)
    
    shodan_scanner = ShodanScanner(config.SHODAN_API_KEY, db_manager)
    cert_pattern = "*.edu.tw"  # 測試用的憑證模式
    
    try:
        shodan_result = shodan_scanner.scan(
            cert_pattern,
            country=config.DEFAULT_COUNTRY,
            port=config.DEFAULT_PORT
        )
        
        shodan_vt_targets = shodan_result.vt_query_targets if shodan_result.vt_query_targets else shodan_result.domains
        shodan_vt_set = set(shodan_vt_targets) if shodan_vt_targets else set()
        
        if not shodan_result.domains:
            print("Shodan 沒有找到相關域名")
        else:
            print(f"Shodan 找到 {len(shodan_result.domains)} 個域名")
        print(f"Shodan VT 查詢目標: {len(shodan_vt_set)} 個")
        
        if shodan_vt_targets:
            print("前 10 個 Shodan VT 目標:")
            for i, target in enumerate(list(shodan_vt_set)[:10], 1):
                print(f"  {i}. {target}")
        
        # 將 Shodan 結果匯入資料庫
        print("\n匯入 Shodan VT 目標到資料庫...")
        shodan_imported = db_manager.import_shodan_vt_targets(list(shodan_vt_set))
        print(f"Shodan 匯入了 {shodan_imported} 個新的 root_domain")
                
    except Exception as e:
        print(f"Shodan 搜尋失敗: {e}")
        shodan_vt_set = set()
        shodan_vt_targets = []
    
    # ========== 步驟 1.5: 匯入 xlsx root_domain 並合併 ==========
    print("\n【步驟 1.5】匯入 xlsx Root Domain 並合併 Shodan 結果")
    print("-" * 40)
    
    # 匯入 xlsx
    xlsx_imported = db_manager.import_root_domains_from_xlsx("institution")
    print(f"xlsx 匯入了 {xlsx_imported} 個新的 root_domain")
    
    # 取得 xlsx 的 root_domain（source='xlsx'）
    xlsx_root_domains = db_manager.get_all_root_domains(source="xlsx")
    print(f"xlsx 來源的 root_domain: {len(xlsx_root_domains)} 個")
    
    if xlsx_root_domains:
        print("前 10 個 xlsx root_domain:")
        for i, rd in enumerate(xlsx_root_domains[:10], 1):
            print(f"  {i}. {rd}")
    
    # ========== 合併：Shodan 優先，xlsx 補充 ==========
    print("\n【合併結果】")
    print("-" * 40)
    
    # 合併：Shodan 優先，xlsx 補充（去除已存在於 Shodan 結果的）
    xlsx_only = [rd for rd in xlsx_root_domains if rd not in shodan_vt_set]
    vt_targets = list(shodan_vt_targets or []) + xlsx_only
    
    print(f"Shodan 來源: {len(shodan_vt_set)} 個")
    print(f"xlsx 補充 (不在 Shodan 中): {len(xlsx_only)} 個")
    print(f"合併後總計: {len(vt_targets)} 個 VT 查詢目標")
    
    # 顯示重疊的部分
    overlap = [rd for rd in xlsx_root_domains if rd in shodan_vt_set]
    if overlap:
        print(f"\n重疊 (同時在 Shodan 和 xlsx 中): {len(overlap)} 個")
        for i, rd in enumerate(overlap[:5], 1):
            print(f"  {i}. {rd}")
        if len(overlap) > 5:
            print(f"  ... 還有 {len(overlap) - 5} 個")
    
    # ========== 檢查資料庫狀態 ==========
    print("\n【資料庫狀態】")
    print("-" * 40)
    
    all_root_domains_in_db = db_manager.get_all_root_domains()
    shodan_source_count = len(db_manager.get_all_root_domains(source="shodan"))
    xlsx_source_count = len(db_manager.get_all_root_domains(source="xlsx"))
    none_source_count = len(all_root_domains_in_db) - shodan_source_count - xlsx_source_count
    
    print(f"資料庫路徑: {TEST_DB_PATH}")
    print(f"root_domain 資料表總筆數: {len(all_root_domains_in_db)}")
    print(f"  - source='shodan': {shodan_source_count} 筆")
    print(f"  - source='xlsx': {xlsx_source_count} 筆")
    print(f"  - source=NULL: {none_source_count} 筆")
    
    # ========== 最終 VT 查詢列表 ==========
    print("\n" + "=" * 60)
    print("【最終 VirusTotal 查詢列表】（步驟 2 將使用此列表）")
    print("=" * 60)
    print(f"總計: {len(vt_targets)} 個目標")
    
    if len(vt_targets) <= 50:
        print("\n完整列表:")
        for i, target in enumerate(vt_targets, 1):
            source_tag = "[Shodan]" if target in shodan_vt_set else "[xlsx]"
            print(f"  {i:3d}. {source_tag:8s} {target}")
    else:
        print("\n前 30 個目標:")
        for i, target in enumerate(vt_targets[:30], 1):
            source_tag = "[Shodan]" if target in shodan_vt_set else "[xlsx]"
            print(f"  {i:3d}. {source_tag:8s} {target}")
        print(f"  ... 省略 {len(vt_targets) - 50} 個 ...")
        print("\n後 20 個目標:")
        for i, target in enumerate(vt_targets[-20:], len(vt_targets) - 19):
            source_tag = "[Shodan]" if target in shodan_vt_set else "[xlsx]"
            print(f"  {i:3d}. {source_tag:8s} {target}")
    
    return vt_targets, db_manager


if __name__ == "__main__":
    vt_targets, db_manager = test_root_domain_merge()
    
    # 將結果存到檔案
    output_file = "vt_targets_list.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# VirusTotal 查詢目標列表\n")
        f.write(f"# 總計: {len(vt_targets)} 個\n")
        f.write(f"# 生成時間: {datetime.now()}\n")
        f.write(f"# 測試資料庫: {TEST_DB_PATH}\n")
        f.write("\n")
        for target in vt_targets:
            f.write(f"{target}\n")
    
    print(f"\n[OK] 結果已存到 {output_file}")
    print(f"[OK] 測試資料庫已建立: {TEST_DB_PATH}")
    print("\n下一步：步驟 2 將對這 {} 個目標執行 VirusTotal + Shodan FQDN 查詢".format(len(vt_targets)))
