"""
Shodan FQDN DNS 掃描器
使用 Shodan DNS API 以分頁方式取得指定 domain 的完整子網域清單（僅 type='A' 記錄）。
不回傳 IP，所有 IP 解析交由 dns.resolver 處理。
"""
import shodan
import time
from typing import List, Set
from utils.logger import get_logger

logger = get_logger("scanners.shodan_fqdn")


class ShodanFqdnScanner:
    """Shodan DNS 子網域掃描器（分頁查詢，過濾 A、AAAA、CNAME record）"""

    def __init__(self, api_key: str, page_delay: float = 1.0):
        self.api_key = api_key
        self.api = shodan.Shodan(api_key)
        self.page_delay = page_delay  # 每頁間延遲，避免過度頻繁

    def get_subdomains_with_a_record(self, domain: str, max_empty_pages: int = 3, max_pages: int = 100) -> List[dict]:
        """
        使用分頁方式查詢指定 domain 的所有子網域，只保留 type='A、AAAA、CNAME' 的記錄。
        不回傳 IP，所有 DNS 解析交由外部處理。
        
        Args:
            domain: 根網域，例如 "ncku.edu.tw"
            max_empty_pages: 連續空頁數量上限，達到後停止查詢
            max_pages: 最大查詢頁數，防止無限循環
            
        Returns:
            List of dict，例如 [{"fqdn": "www.ncku.edu.tw", "parent_domain_name": None}, {"fqdn": "alias.ncku.edu.tw", "parent_domain_name": "target.ncku.edu.tw"}]
        """
        logger.info(f"[Shodan DNS] 開始分頁查詢 {domain} 的子網域（僅 A、AAAA、CNAME record）...")
        
        seen: Set[str] = set()
        results: List[dict] = []  # 儲存完整結果
        page = 1
        total_records = 0
        empty_pages_count = 0  # 連續空頁計數器
        last_page_size = None  # 記錄上一頁的大小，用於偵測循環
        
        try:
            while True:
                try:
                    # 使用分頁查詢 DNS 記錄
                    result = self.api.dns.domain_info(domain, page=page)
                    
                    # 第一頁時記錄總數
                    if page == 1:
                        # 有些 API 可能不返回 total，用 data 長度判斷
                        data = result.get('data', [])
                        logger.info(f"[Shodan DNS] 第 1 頁取得 {len(data)} 筆記錄")
                    
                    data = result.get('data', [])
                    
                    # 如果沒有資料，表示已經到最後一頁
                    if not data:
                        logger.info(f"[Shodan DNS] 第 {page} 頁無資料，查詢結束")
                        break
                    
                    # 檢測是否進入重複循環（相同的頁大小重複出現）
                    current_page_size = len(data)
                    if last_page_size is not None and current_page_size == last_page_size and page > 10:
                        logger.warning(f"[Shodan DNS] 偵測到可能的數據重複（頁大小: {current_page_size}），停止查詢")
                        break
                    last_page_size = current_page_size
                    
                    # 達到最大頁數限制
                    if page > max_pages:
                        logger.warning(f"[Shodan DNS] 達到最大頁數限制 ({max_pages})，停止查詢")
                        break

                    # 過濾出 A、AAAA、CNAME Record 的記錄
                    page_a_count = 0
                    for record in data:
                        if record.get('type') not in ['A', 'AAAA', 'CNAME']:
                            continue
                        
                        subdomain = record.get('subdomain', '').strip()
                        
                        # 組成完整 FQDN
                        if subdomain == '@' or subdomain == '':
                            fqdn = domain
                        else:
                            fqdn = f"{subdomain}.{domain}"
                        
                        # 去重
                        if fqdn not in seen:
                            seen.add(fqdn)
                            page_a_count += 1
                            
                            # 提取 parent_domain_name（僅 CNAME 記錄有）
                            parent_domain_name = None
                            if record.get('type') == 'CNAME':
                                parent_domain_name = record.get('value', '').strip()
                                logger.debug(f"  CNAME record: {fqdn} -> {parent_domain_name}")
                            else:
                                logger.debug(f"  {record.get('type')} record: {fqdn}")
                            
                            # 添加到結果列表
                            results.append({
                                "fqdn": fqdn,
                                "parent_domain_name": parent_domain_name
                            })
                    
                    total_records += len(data)
                    
                    # 更新空頁計數器
                    if page_a_count == 0:
                        empty_pages_count += 1
                        logger.debug(f"[Shodan DNS] 空頁計數: {empty_pages_count}/{max_empty_pages}")
                    else:
                        empty_pages_count = 0  # 重置計數器
                    
                    logger.info(f"[Shodan DNS] 第 {page} 頁：{len(data)} 筆記錄，{page_a_count} 筆 A、AAAA、CNAME record（累計: {len(seen)}）")
                    
                    # 如果連續太多空頁，停止查詢
                    if empty_pages_count >= max_empty_pages:
                        logger.info(f"[Shodan DNS] 連續 {max_empty_pages} 頁無有效記錄，停止查詢")
                        break
                    
                    # 繼續下一頁
                    page += 1
                    time.sleep(self.page_delay)
                    
                except shodan.APIError as e:
                    # 如果是 404 或其他錯誤，可能表示沒有更多頁
                    if "404" in str(e) or "No information" in str(e):
                        logger.info(f"[Shodan DNS] API 回應無更多資料（頁 {page}），查詢結束")
                        break
                    else:
                        logger.error(f"[Shodan DNS] API 錯誤（頁 {page}）: {e}")
                        # API 錯誤時等待更久一點再重試
                        if "rate limit" in str(e).lower():
                            logger.info("[Shodan DNS] 命中速率限制，等待 5 秒...")
                            time.sleep(5)
                        break
                except Exception as e:
                    logger.error(f"[Shodan DNS] 未知錯誤（頁 {page}）: {e}")
                    break
                        
        except Exception as e:
            logger.error(f"[Shodan DNS] 查詢失敗: {e}")
        
        # 按 fqdn 排序結果
        results.sort(key=lambda x: x["fqdn"])
        logger.info(f"[Shodan DNS] {domain} 完成查詢，共 {len(results)} 個 A、AAAA、CNAME record 子網域（總記錄數 {total_records}）")
        return results
