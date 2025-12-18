# database/repository.py
from __future__ import annotations
from typing import Optional, Tuple, List
from datetime import datetime

from sqlalchemy import select, func, distinct, text
from sqlalchemy.exc import IntegrityError

from database.session import create_session_factory, db_session
from database.models import Base, IP, RootDomain, Domain, Area, Domain_ip, Otx_httpscan
from models.website import Website
from utils.logger import get_logger
from config import Config

logger = get_logger("database.manager.orm")

class DatabaseManagerORM:
    """以 SQLAlchemy ORM 實作的資料庫管理器"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.engine, self.SessionFactory = create_session_factory(db_path)
        self._init_database()

    def _init_database(self) -> None:
        Base.metadata.create_all(self.engine)
        
        logger.info(f"已建立/確認資料表（ORM）：{self.db_path}")
        # 自動匯入 area 資料（若存在檔案且表為空）
        try:
            csv_path = getattr(Config, 'CITY_DOMAIN_CSV_PATH', 'domain_of_city.csv')
            if csv_path:
                with db_session(self.SessionFactory) as session:
                    has_any = session.execute(select(func.count(Area.id))).scalar_one()
                import os
                if has_any == 0 and os.path.isfile(csv_path):
                    inserted = self.import_area_from_csv(csv_path)
                    logger.info(f"area 初始化匯入：{inserted} 筆（來源: {csv_path}）")
        except Exception as e:
            logger.warning(f"初始化匯入 area 失敗：{e}")

    # ---------- 內部工具 ----------
    def _get_or_create_ip(self, session, ipv4: Optional[str] = None, ipv6: Optional[str] = None) -> IP:
        """
        獲取或創建 IP 記錄（支援 IPv4/IPv6）
        """
        if not ipv4 and not ipv6:
            raise ValueError("必須提供 IPv4 或 IPv6 地址")
        
        # 查找現有IP記錄
        ip = session.execute(
            select(IP).where(
                (IP.ipv4 == ipv4) if ipv4 else IP.ipv4.is_(None),
                (IP.ipv6 == ipv6) if ipv6 else IP.ipv6.is_(None)
            )
        ).scalar_one_or_none()
        
        if ip:
            return ip
        
        # 創建新IP記錄
        ip = IP(ipv4=ipv4, ipv6=ipv6)
        session.add(ip)
        session.flush()  # 取得自動編號 id
        return ip

    def _get_or_create_root_domain(self, session, root_domain_name: Optional[str]) -> Optional[RootDomain]:
        if not root_domain_name:
            return None
        root_domain = session.execute(select(RootDomain).where(RootDomain.name == root_domain_name)).scalar_one_or_none()
        if root_domain:
            return root_domain
        root_domain = RootDomain(name=root_domain_name)
        session.add(root_domain)
        session.flush()
        return root_domain

    def get_or_create_root_domain(self, root_domain_name: str) -> RootDomain:
        """
        獲取或創建根域名記錄（公有方法，供 domain_hierarchy 使用）
        """
        with db_session(self.SessionFactory) as session:
            return self._get_or_create_root_domain(session, root_domain_name)
    
    def get_root_domain_by_name(self, root_domain_name: str) -> Optional[RootDomain]:
        """
        根據名稱獲取根域名記錄
        """
        with db_session(self.SessionFactory) as session:
            return session.execute(
                select(RootDomain).where(RootDomain.name == root_domain_name)
            ).scalar_one_or_none()

    # ---------- 對外 API ----------
    def save_website(self, website: Website, root_domain_name: Optional[str] = None, when_latest_otx_checked: Optional[datetime] = None) -> bool:
        """
        保存網站資料（使用新的域名階層結構）
        
        注意：此方法假設域名階層已經通過 domain_hierarchy 模組建立
        支援多 IP 關聯（一個 domain 可對應多個 IP）
        """
        with db_session(self.SessionFactory) as session:
            try:
                # 讀取 Website 物件上暫存的 IP 列表（新格式）
                ipv4_list = getattr(website, "ipv4_list", []) or []
                ipv6_list = getattr(website, "ipv6_list", []) or []
                
                # 向下相容：支援舊的單一 IP 格式
                if not ipv4_list:
                    ipv4_val = getattr(website, "ipv4", None)
                    if ipv4_val:
                        ipv4_list = [ipv4_val]
                if not ipv6_list:
                    ipv6_val = getattr(website, "ipv6", None)
                    if ipv6_val:
                        ipv6_list = [ipv6_val]
                
                # 查找域名（使用新的階層結構）
                domain = self._find_domain_by_fqdn(session, website.fqdn)
                if not domain:
                    logger.warning(f"找不到域名記錄：{website.fqdn}，可能域名階層尚未建立")
                    return False
                
                root_domain = self._get_or_create_root_domain(session, root_domain_name)
                
                # 更新域名記錄
                if root_domain:
                    domain.root_id = root_domain.id
                domain.when_crawled = website.when_crawled
                domain.when_latest_otx_checked = when_latest_otx_checked
                
                # 處理 IP 關聯（多對多）- 處理所有 IPv4
                saved_ips = []
                for ipv4 in ipv4_list:
                    ip = self._get_or_create_ip(session, ipv4=ipv4, ipv6=None)
                    self._create_domain_ip_relation(session, domain.id, ip.id)
                    saved_ips.append(ipv4)
                
                # 處理 IP 關聯（多對多）- 處理所有 IPv6
                for ipv6 in ipv6_list:
                    ip = self._get_or_create_ip(session, ipv4=None, ipv6=ipv6)
                    self._create_domain_ip_relation(session, domain.id, ip.id)
                    saved_ips.append(ipv6)
                
                saved_ip_display = ",".join(saved_ips) if saved_ips else "(no IP)"
                
                logger.info(
                    f"更新域名：{website.fqdn} -> [{len(saved_ips)} IPs: {saved_ip_display[:50]}{'...' if len(saved_ip_display) > 50 else ''}] "
                    f"root_domain={root_domain_name or '-'} "
                    f"otx={'T' if when_latest_otx_checked else 'F'}"
                )
                return True
                
            except Exception as e:
                logger.error(f"保存域名失敗 {website.fqdn}: {e}")
                return False
    
    def _create_domain_ip_relation(self, session, domain_id: int, ip_id: int) -> None:
        """
        創建 domain_ip 關聯（如果不存在）
        """
        existing_relation = session.execute(
            select(Domain_ip).where(
                Domain_ip.domain_id == domain_id,
                Domain_ip.ip_id == ip_id
            )
        ).scalar_one_or_none()
        
        if not existing_relation:
            domain_ip_relation = Domain_ip(domain_id=domain_id, ip_id=ip_id)
            session.add(domain_ip_relation)
    
    def _find_domain_by_fqdn(self, session, fqdn: str) -> Optional[Domain]:
        """
        通過 FQDN 查找域名記錄（階層式存法）
        例如：health.mdic.ncku.edu.tw
        -> 從 tw 開始，逐層往下找 edu -> ncku -> mdic -> health
        """
        parts = fqdn.split('.')
        if not parts:
            return None
        
        # 從最右邊（根域名）開始查找
        current_domain = None
        
        # 先查找根域名（最後一部分，如 "tw"）
        root_label = parts[-1]
        current_domain = session.execute(
            select(Domain).where(
                Domain.leftmost_label == root_label,
                Domain.parent_domain_id.is_(None)
            )
        ).scalar_one_or_none()
        
        if not current_domain:
            return None
        
        # 如果只有一個部分（如"tw"），直接返回
        if len(parts) == 1:
            return current_domain
        
        # 從右到左逐層查找：tw -> edu -> ncku -> mdic -> health
        for i in range(len(parts) - 2, -1, -1):
            label = parts[i]
            current_domain = session.execute(
                select(Domain).where(
                    Domain.leftmost_label == label,
                    Domain.parent_domain_id == current_domain.id
                )
            ).scalar_one_or_none()
            
            if not current_domain:
                return None
        
        return current_domain

    def save_websites_batch(self, websites: List[Website], root_domain_name: Optional[str] = None, when_latest_otx_checked: Optional[datetime] = None) -> int:
        saved = 0
        for w in websites:
            if self.save_website(w, root_domain_name, when_latest_otx_checked):
                saved += 1
        return saved

    def get_website_by_fqdn(self, fqdn_name: str) -> Optional[Website]:
        """
        通過 FQDN 查找網站資料（使用新的域名階層結構）
        返回的 Website 物件包含所有關聯的 IP（ipv4_list, ipv6_list）
        """
        with db_session(self.SessionFactory) as session:
            # 查找域名
            domain = self._find_domain_by_fqdn(session, fqdn_name)
            if not domain:
                return None
            
            # 獲取所有相關的 IP 資料（透過 domain_ip 關聯）
            domain_ip_relations = session.execute(
                select(Domain_ip).where(Domain_ip.domain_id == domain.id)
            ).scalars().all()
            
            # 收集所有 IP
            ipv4_list = []
            ipv6_list = []
            
            for relation in domain_ip_relations:
                ip = session.execute(
                    select(IP).where(IP.id == relation.ip_id)
                ).scalar_one_or_none()
                if ip:
                    if ip.ipv4:
                        ipv4_list.append(ip.ipv4)
                    if ip.ipv6:
                        ipv6_list.append(ip.ipv6)
            
            website = Website(
                fqdn=fqdn_name,
                url=None,
                protocol=None,
                status_code=None,
                redirect_to=None,
                title=None,
                when_crawled=domain.when_crawled if isinstance(domain.when_crawled, datetime) else datetime.fromisoformat(str(domain.when_crawled)) if domain.when_crawled else None
            )
            
            # 設定 IP 列表屬性（新格式）
            setattr(website, "ipv4_list", ipv4_list)
            setattr(website, "ipv6_list", ipv6_list)
            
            # 向下相容：設定單一 IP 屬性（取第一個）
            website.ipv4 = ipv4_list[0] if ipv4_list else None
            website.ipv6 = ipv6_list[0] if ipv6_list else None
            
            return website

    def get_statistics(self) -> Tuple[int, int]:
        """
        獲取統計資料（使用新的域名階層結構）
        """
        with db_session(self.SessionFactory) as session:
            # 總域名數量
            total = session.execute(select(func.count(Domain.id))).scalar_one()
            
            # 唯一 IP 數量（通過 domain_ip 關聯計算）
            uniq_ip = session.execute(
                select(func.count(distinct(Domain_ip.ip_id)))
            ).scalar_one()
            
            return total, uniq_ip

    # ---------- 匯入 Area CSV ----------
    def import_area_from_csv(self, csv_path: str, encoding: str = "utf-8") -> int:
        """從 CSV 匯入 area 資料（支援 sn,domain,city 或 name,domain 格式）"""
        import csv
        inserted = 0
        with db_session(self.SessionFactory) as session:
            with open(csv_path, "r", encoding=encoding, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = (row.get("name") or row.get("city") or "").strip()
                    domain = (row.get("domain") or "").strip().lower()
                    if not name or not domain:
                        continue
                    exists = session.execute(select(Area).where(Area.domain == domain)).scalar_one_or_none()
                    if exists:
                        continue
                    area = Area(name=name, domain=domain)
                    session.add(area)
                    inserted += 1
        logger.info(f"Area 匯入完成，新增 {inserted} 筆")
        return inserted

    def find_area_domain(self, domain: str) -> Optional[str]:
        """查詢 domain 是否在 area 表中，返回匹配的 area.domain"""
        with db_session(self.SessionFactory) as session:
            result = session.execute(
                select(Area.domain).where(Area.domain == domain)
            ).scalar_one_or_none()
            return result

    # ---------- OTX HTTP Scans ----------
    def save_http_scans(self, fqdn: str, http_scans: List[dict]) -> int:
        """
        儲存 OTX HTTP Scans 資料到 otx_httpscan 資料表
        
        Args:
            fqdn: 完整域名
            http_scans: OTX API 返回的 http_scans 資料列表
                       每筆包含 {"name": "...", "value": "..."}
        
        Returns:
            成功寫入的筆數
        """
        if not http_scans:
            return 0
        
        with db_session(self.SessionFactory) as session:
            try:
                # 查找域名
                domain = self._find_domain_by_fqdn(session, fqdn)
                if not domain:
                    logger.warning(f"找不到域名記錄：{fqdn}，無法儲存 http_scans")
                    return 0
                
                inserted = 0
                for scan in http_scans:
                    name = scan.get("name", "")
                    value = scan.get("value", "")
                    
                    # value 可能是數字，轉成字串
                    if not isinstance(value, str):
                        value = str(value)
                    
                    if not name:
                        continue
                    
                    # 建立新記錄
                    record = Otx_httpscan(
                        domain_id=domain.id,
                        name=name,
                        value=value
                    )
                    session.add(record)
                    inserted += 1
                
                logger.info(f"儲存 {fqdn} 的 {inserted} 筆 http_scans 資料")
                return inserted
                
            except Exception as e:
                logger.error(f"儲存 {fqdn} http_scans 失敗: {e}")
                return 0

    def save_http_scans_batch(self, http_scans_dict: dict[str, List[dict]]) -> int:
        """
        批次儲存多個 FQDN 的 OTX HTTP Scans 資料
        
        Args:
            http_scans_dict: {fqdn: [http_scans_data]} 的字典
        
        Returns:
            成功寫入的總筆數
        """
        total_inserted = 0
        for fqdn, scans in http_scans_dict.items():
            inserted = self.save_http_scans(fqdn, scans)
            total_inserted += inserted
        
        logger.info(f"批次儲存 http_scans 完成，共 {total_inserted} 筆")
        return total_inserted
