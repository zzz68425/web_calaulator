# database/repository.py
from __future__ import annotations
from typing import Optional, Tuple, List
from datetime import datetime

from sqlalchemy import select, func, distinct
from sqlalchemy.exc import IntegrityError

from database.session import create_session_factory, db_session
from database.models import Base, IP, RootDomain, Fqdn, Institution
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
        # 自動匯入 institution 資料（若存在檔案且表為空）
        try:
            csv_path = getattr(Config, 'CITY_DOMAIN_CSV_PATH', 'domain_of_city.csv')
            if csv_path:
                with db_session(self.SessionFactory) as session:
                    has_any = session.execute(select(func.count(Institution.sn))).scalar_one()
                import os
                if has_any == 0 and os.path.isfile(csv_path):
                    inserted = self.import_institution_from_csv(csv_path)
                    logger.info(f"institution 初始化匯入：{inserted} 筆（來源: {csv_path}）")
        except Exception as e:
            logger.warning(f"初始化匯入 institution 失敗：{e}")

    # ---------- 內部工具 ----------
    def _get_or_create_ip(self, session, address: str) -> IP:
        ip = session.execute(select(IP).where(IP.address == address)).scalar_one_or_none()
        if ip:
            return ip
        ip_type = "IPv6" if ":" in address else "IPv4"
        ip = IP(address=address, type=ip_type)
        session.add(ip)
        session.flush()  # 取得自動編號 sn
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
    def save_website(self, website: Website, root_domain_name: Optional[str] = None) -> bool:
        """
        將 Website（只用 fqdn/ip/when_crawled）對映到三表：
        - ip: get-or-create
        - root_domain: 依 root_domain_name 選擇性掛載
        - fqdn: upsert by name（更新 ip_sn / root_sn / when_crawled）
        """
        with db_session(self.SessionFactory) as session:
            try:
                ip = self._get_or_create_ip(session, website.ip)
                root_domain = self._get_or_create_root_domain(session, root_domain_name)

                fq = session.execute(select(Fqdn).where(Fqdn.name == website.fqdn)).scalar_one_or_none()
                if fq:
                    fq.ip_sn = ip.sn
                    if root_domain:
                        fq.root_sn = root_domain.sn
                    fq.when_crawled = website.when_crawled
                else:
                    fq = Fqdn(
                        name=website.fqdn,
                        ip_sn=ip.sn,
                        root_sn=(root_domain.sn if root_domain else None),
                        when_crawled=website.when_crawled,
                    )
                    session.add(fq)

                logger.info(f"寫入/更新：{website.fqdn} -> {website.ip} root_domain={root_domain_name or '-'}")
                return True
            except IntegrityError as e:
                logger.error(f"唯一性衝突或外鍵錯誤：{e}")
                return False
            except Exception as e:
                logger.error(f"儲存失敗：{e}")
                return False

    def save_websites_batch(self, websites: List[Website], root_domain_name: Optional[str] = None) -> int:
        saved = 0
        for w in websites:
            if self.save_website(w, root_domain_name):
                saved += 1
        return saved

    def get_website_by_fqdn(self, fqdn_name: str) -> Optional[Website]:
        with db_session(self.SessionFactory) as session:
            row = session.execute(
                select(Fqdn.name, IP.address, Fqdn.when_crawled)
                .join(IP, IP.sn == Fqdn.ip_sn)
                .where(Fqdn.name == fqdn_name)
            ).first()
            if not row:
                return None
            name, ip_addr, when = row
            return Website(
                fqdn=name,
                ip=ip_addr,
                url=None,
                protocol=None,
                status_code=None,
                redirect_to=None,
                title=None,
                when_crawled=when if isinstance(when, datetime) else datetime.fromisoformat(str(when))
            )

    def get_statistics(self) -> Tuple[int, int]:
        with db_session(self.SessionFactory) as session:
            total = session.execute(select(func.count(Fqdn.sn))).scalar_one()
            uniq_ip = session.execute(select(func.count(distinct(Fqdn.ip_sn)))).scalar_one()
            return total, uniq_ip

    # ---------- 匯入 Institution CSV ----------
    def import_institution_from_csv(self, csv_path: str, encoding: str = "utf-8") -> int:
        """從 CSV 匯入 institution 資料（支援 sn,domain,city 或 name,domain 格式）"""
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
                    exists = session.execute(select(Institution).where(Institution.domain == domain)).scalar_one_or_none()
                    if exists:
                        continue
                    inst = Institution(name=name, domain=domain)
                    session.add(inst)
                    inserted += 1
        logger.info(f"Institution 匯入完成，新增 {inserted} 筆")
        return inserted

    def find_institution_domain(self, domain: str) -> Optional[str]:
        """查詢 domain 是否在 institution 表中，返回匹配的 institution.domain"""
        with db_session(self.SessionFactory) as session:
            result = session.execute(
                select(Institution.domain).where(Institution.domain == domain)
            ).scalar_one_or_none()
            return result
