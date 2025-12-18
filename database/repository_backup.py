# database/repository.py
from __future__ import annotations
from typing import Optional, Tuple, List
from datetime import datetime

from sqlalchemy import select, func, distinct, update
from sqlalchemy.exc import IntegrityError

from database.session import create_session_factory, db_session
from database.models import Base, IP, RootDomain, Domain, Area, Domain_ip
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
        # 自動遷移：若 ip 表仍有 legacy 'address' 欄位，搬移至 ipv4/ipv6 並移除
        try:
            with self.engine.begin() as conn:
                cols = conn.exec_driver_sql("PRAGMA table_info(ip);").fetchall()
                col_names = {c[1] for c in cols}
                if "address" in col_names:
                    has_ipv4 = "ipv4" in col_names
                    has_ipv6 = "ipv6" in col_names
                    ipv4_expr = "ipv4" if has_ipv4 else "CASE WHEN instr(address, ':')=0 THEN address ELSE NULL END"
                    ipv6_expr = "ipv6" if has_ipv6 else "CASE WHEN instr(address, ':')>0 THEN address ELSE NULL END"
                    conn.exec_driver_sql("PRAGMA foreign_keys=OFF;")
                    conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS ip_new (id INTEGER NOT NULL PRIMARY KEY, ipv4 TEXT UNIQUE, ipv6 TEXT UNIQUE);")
                    conn.exec_driver_sql(
                        f"INSERT INTO ip_new (id, ipv4, ipv6) SELECT sn, {ipv4_expr}, {ipv6_expr} FROM ip;"
                    )
                    conn.exec_driver_sql("DROP TABLE ip;")
                    conn.exec_driver_sql("ALTER TABLE ip_new RENAME TO ip;")
                    conn.exec_driver_sql("PRAGMA foreign_keys=ON;")
                    logger.info("已自動遷移 ip.address -> ipv4/ipv6 並移除 address 欄位")
        except Exception as e:
            logger.warning(f"IP 表結構遷移失敗或不需要：{e}")
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
        """以 ipv4/ipv6 組合查找或建立 IP 記錄。

        規則：
        - 以 ipv4 和 ipv6 的組合作為唯一性判斷
        - 相同的組合會復用同一筆 IP 記錄
        - 不同的組合會建立新的 IP 記錄
        """
        # 查詢是否已有相同的 ipv4/ipv6 組合
        existing_ip = session.execute(
            select(IP).where(
                IP.ipv4 == ipv4,
                IP.ipv6 == ipv6
            )
        ).scalar_one_or_none()
        
        if existing_ip:
            return existing_ip
        
        # 沒有找到相同組合，建立新記錄
        ip = IP(ipv4=ipv4, ipv6=ipv6)
        session.add(ip)
        session.flush()
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

    # ---------- 對外 API ----------
    def save_website_with_hierarchy(self, website: Website, root_domain_name: Optional[str] = None, when_latest_otx_checked: Optional[datetime] = None) -> bool:
        """
        保存網站資料到資料庫，使用正確的域名階層結構
        
        Args:
            website: 要儲存的網站資料
            root_domain_name: 根域名（選擇性）
            when_latest_otx_checked: OTX 檢查時間（選擇性）
        
        Returns:
            是否成功儲存
        """
        from domain_hierarchy import DomainHierarchyBuilder
        
        # 先建立域名階層
        hierarchy_builder = DomainHierarchyBuilder(self)
        domain_map = hierarchy_builder.build_domain_hierarchy([website.fqdn])
        
        if website.fqdn not in domain_map:
            logger.error(f"無法建立域名階層: {website.fqdn}")
            return False
        
        domain_id = domain_map[website.fqdn]
        
        # 繼續處理 IP 和關聯
        return self._save_website_with_domain_id(website, domain_id, root_domain_name, when_latest_otx_checked)
    
    def _save_website_with_domain_id(self, website: Website, domain_id: int, root_domain_name: Optional[str] = None, when_latest_otx_checked: Optional[datetime] = None) -> bool:
        """
        使用已知的 domain_id 保存網站資料
        """
        with db_session(self.SessionFactory) as session:
            try:
                # 讀取 Website 物件上暫存的 v4/v6（若有）
                ipv4_val = getattr(website, "ipv4", None)
                ipv6_val = getattr(website, "ipv6", None)
                
                # 取得已存在的 Domain 記錄
                domain = session.get(Domain, domain_id)
                if not domain:
                    logger.error(f"Domain ID {domain_id} 不存在")
                    return False
                    
                root_domain = self._get_or_create_root_domain(session, root_domain_name)

                # 若未提供任何 IP 資訊，僅更新 Domain 的 meta 信息
                no_ip_info = (not ipv4_val and not ipv6_val)
                if no_ip_info:
                    if root_domain:
                        domain.root_id = root_domain.id
                    domain.when_crawled = website.when_crawled
                    domain.when_latest_otx_checked = when_latest_otx_checked
                    saved_ip_display = "(unchanged)"
                else:
                    # 以 ipv4/ipv6 建立或取得 IP 記錄
                    ip = self._get_or_create_ip(session, ipv4_val, ipv6_val)
                    
                    # 更新 Domain 信息
                    if root_domain:
                        domain.root_id = root_domain.id
                    domain.when_crawled = website.when_crawled
                    domain.when_latest_otx_checked = when_latest_otx_checked
                    
                    # 檢查 domain_ip 關聯是否已存在
                    existing_relation = session.execute(
                        select(Domain_ip).where(
                            Domain_ip.domain_id == domain.id,
                            Domain_ip.ip_id == ip.id
                        )
                    ).scalar_one_or_none()
                    
                    if not existing_relation:
                        # 建立 domain_ip 關聯
                        domain_ip_relation = Domain_ip(domain_id=domain.id, ip_id=ip.id)
                        session.add(domain_ip_relation)
                        
                    saved_ip_display = ip.ipv4 or ip.ipv6 or "-"
                    
                logger.info(
                    f"寫入/更新：{website.fqdn} -> {saved_ip_display} root_domain={root_domain_name or '-'} "
                    f"otx={'T' if when_latest_otx_checked else 'F'}"
                )
                return True
            except IntegrityError as e:
                logger.error(f"唯一性衝突或外鍵錯誤：{e}")
                return False
            except Exception as e:
                logger.error(f"儲存失敗：{e}")
                return False

    def save_website(self, website: Website, root_domain_name: Optional[str] = None, when_latest_otx_checked: Optional[datetime] = None) -> bool:
        """
        保存網站資料到資料庫（舊版本，暫時保留以向後相容）
        
        Args:
            website: 要儲存的網站資料
            root_domain_name: 根域名（選擇性）
            when_latest_otx_checked: OTX 檢查時間（選擇性）
        
        Returns:
            是否成功儲存
        """
        with db_session(self.SessionFactory) as session:
            try:
                # 讀取 Website 物件上暫存的 v4/v6（若有）
                ipv4_val = getattr(website, "ipv4", None)
                ipv6_val = getattr(website, "ipv6", None)
                # 嘗試取得已存在的 Domain 記錄（用於僅更新 otx 時不變更 IP 關聯）
                fq = session.execute(select(Domain).where(Domain.leftmost_label == website.fqdn)).scalar_one_or_none()
                root_domain = self._get_or_create_root_domain(session, root_domain_name)

                # 若未提供任何 IP 資訊（ipv4/ipv6 皆無），僅更新現有 Domain 的 meta，不變更 IP 關聯
                no_ip_info = (not ipv4_val and not ipv6_val)
                if no_ip_info and fq:
                    if root_domain:
                        fq.root_id = root_domain.id
                    fq.when_crawled = website.when_crawled
                    fq.when_latest_otx_checked = when_latest_otx_checked
                    saved_ip_display = "(unchanged)"
                else:
                    # 以 ipv4/ipv6 建立或取得 IP 記錄
                    ip = self._get_or_create_ip(
                        session, ipv4_val, ipv6_val
                    )
                    root_domain_id = root_domain.id if root_domain else None
                    
                    if fq:
                        # 更新現有域名
                        if root_domain:
                            fq.root_id = root_domain.id
                        fq.when_crawled = website.when_crawled
                        fq.when_latest_otx_checked = when_latest_otx_checked
                        
                        # 檢查 domain_ip 關聯是否已存在
                        existing_relation = session.execute(
                            select(Domain_ip).where(
                                Domain_ip.domain_id == fq.id,
                                Domain_ip.ip_id == ip.id
                            )
                        ).scalar_one_or_none()
                        
                        if not existing_relation:
                            domain_ip_relation = Domain_ip(domain_id=fq.id, ip_id=ip.id)
                            session.add(domain_ip_relation)
                    else:
                        # 建立新的域名
                        fq = Domain(
                            leftmost_label=website.fqdn,
                            root_id=(root_domain.id if root_domain else None),
                            parent_domain_id=None,  # 將來解析域名階層時設定
                            when_crawled=website.when_crawled,
                            when_latest_otx_checked=when_latest_otx_checked,
                        )
                        session.add(fq)
                        session.flush()  # 確保 fq.id 可用
                        
                        # 建立 domain_ip 關聯
                        domain_ip_relation = Domain_ip(domain_id=fq.id, ip_id=ip.id)
                        session.add(domain_ip_relation)
                        
                    saved_ip_display = ip.ipv4 or ip.ipv6 or "-"
                logger.info(
                    f"寫入/更新：{website.fqdn} -> {saved_ip_display} root_domain={root_domain_name or '-'} "
                    f"otx={'T' if when_latest_otx_checked else 'F'}"
                )
                return True
            except IntegrityError as e:
                logger.error(f"唯一性衝突或外鍵錯誤：{e}")
                return False
            except Exception as e:
                logger.error(f"儲存失敗：{e}")
                return False
                else:
                    # 以 ipv4/ipv6 建立或取得 IP 記錄
                    ip = self._get_or_create_ip(
                        session,
                        ipv4=ipv4_val,
                        ipv6=ipv6_val
                    )
                    if fq:
                        # 更新現有域名
                        if root_domain:
                            fq.root_id = root_domain.id
                        fq.when_crawled = website.when_crawled
                        fq.when_latest_otx_checked = when_latest_otx_checked
                        # TODO: parent_domain_id 處理延後到第二階段
                        
                        # 檢查是否已經有 domain_ip 關聯
                        existing_domain_ip = session.execute(
                            select(Domain_ip).where(
                                Domain_ip.domain_id == fq.id,
                                Domain_ip.ip_id == ip.id
                            )
                        ).scalar_one_or_none()
                        
                        if not existing_domain_ip:
                            # 建立新的 domain_ip 關聯
                            domain_ip_relation = Domain_ip(domain_id=fq.id, ip_id=ip.id)
                            session.add(domain_ip_relation)
                    else:
                        # 建立新的域名
                        fq = Domain(
                            leftmost_label=website.fqdn,
                            root_id=(root_domain.id if root_domain else None),
                            parent_domain_id=None,  # 將來解析域名階層時設定
                            when_crawled=website.when_crawled,
                            when_latest_otx_checked=when_latest_otx_checked,
                        )
                        session.add(fq)
                        session.flush()  # 確保 fq.id 可用
                        
                        # 建立 domain_ip 關聯
                        domain_ip_relation = Domain_ip(domain_id=fq.id, ip_id=ip.id)
                        session.add(domain_ip_relation)
                        
                    saved_ip_display = ip.ipv4 or ip.ipv6 or "-"
                logger.info(
                    f"寫入/更新：{website.fqdn} -> {saved_ip_display} root_domain={root_domain_name or '-'} "
                    f"otx={'T' if when_latest_otx_checked else 'F'}"
                )
                return True
            except IntegrityError as e:
                logger.error(f"唯一性衝突或外鍵錯誤：{e}")
                return False
            except Exception as e:
                logger.error(f"儲存失敗：{e}")
                return False

    def save_websites_batch(self, websites: List[Website], root_domain_name: Optional[str] = None, when_latest_otx_checked: Optional[datetime] = None) -> int:
        saved = 0
        for w in websites:
            if self.save_website(w, root_domain_name, when_latest_otx_checked=when_latest_otx_checked):
                saved += 1
        return saved

    def get_website_by_fqdn(self, fqdn_name: str) -> Optional[Website]:
        with db_session(self.SessionFactory) as session:
            row = session.execute(
                select(Domain.leftmost_label, IP.ipv4, IP.ipv6, Domain.when_crawled, Domain.when_latest_otx_checked, Domain.when_latest_certificate_checked, Domain.parent_domain_id)
                .join(Domain_ip, Domain_ip.domain_id == Domain.id)
                .join(IP, IP.id == Domain_ip.ip_id)
                .where(Domain.leftmost_label == fqdn_name)
            ).first()
            if not row:
                return None
            name, ipv4, ipv6, when, otx_checked, cert_checked, parent_domain_id = row
            site = Website(
                fqdn=name,
                url=None,
                protocol=None,
                status_code=None,
                redirect_to=None,
                title=None,
                when_crawled=when if isinstance(when, datetime) else datetime.fromisoformat(str(when))
            )
            # 附帶 ipv4/ipv6 屬性，property 會自動從這裡取得 ip
            setattr(site, "ipv4", ipv4)
            setattr(site, "ipv6", ipv6)
            setattr(site, "when_latest_otx_checked", otx_checked)
            setattr(site, "when_latest_certificate_checked", cert_checked)
            setattr(site, "parent_domain_id", parent_domain_id)  # 現在是 ID 而非名稱
            return site

    def get_statistics(self) -> Tuple[int, int]:
        with db_session(self.SessionFactory) as session:
            total = session.execute(select(func.count(Domain.id))).scalar_one()
            uniq_ip = session.execute(
                select(func.count(distinct(Domain_ip.ip_id)))
                .select_from(Domain_ip)
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

