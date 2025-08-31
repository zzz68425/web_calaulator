# database/repository.py
from __future__ import annotations
from typing import Optional, Tuple, List
from datetime import datetime

from sqlalchemy import select, func, distinct
from sqlalchemy.exc import IntegrityError

from database.session import create_session_factory, db_session
from database.models import Base, IP, Certificate, Fqdn
from models.website import Website
from utils.logger import get_logger

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

    def _get_or_create_cert(self, session, cert_name: Optional[str]) -> Optional[Certificate]:
        if not cert_name:
            return None
        cert = session.execute(select(Certificate).where(Certificate.name == cert_name)).scalar_one_or_none()
        if cert:
            return cert
        cert = Certificate(name=cert_name)
        session.add(cert)
        session.flush()
        return cert

    # ---------- 對外 API ----------
    def save_website(self, website: Website, certificate_name: Optional[str] = None) -> bool:
        """
        將 Website（只用 fqdn/ip/when_crawled）對映到三表：
        - ip: get-or-create
        - certificate: 依 certificate_name 選擇性掛載
        - fqdn: upsert by name（更新 ip_sn / certificate_sn / when_crawled）
        """
        with db_session(self.SessionFactory) as session:
            try:
                ip = self._get_or_create_ip(session, website.ip)
                cert = self._get_or_create_cert(session, certificate_name)

                fq = session.execute(select(Fqdn).where(Fqdn.name == website.fqdn)).scalar_one_or_none()
                if fq:
                    fq.ip_sn = ip.sn
                    if cert:
                        fq.certificate_sn = cert.sn
                    fq.when_crawled = website.when_crawled
                else:
                    fq = Fqdn(
                        name=website.fqdn,
                        ip_sn=ip.sn,
                        certificate_sn=(cert.sn if cert else None),
                        when_crawled=website.when_crawled,
                    )
                    session.add(fq)

                logger.info(f"寫入/更新：{website.fqdn} -> {website.ip} cert={certificate_name or '-'}")
                return True
            except IntegrityError as e:
                logger.error(f"唯一性衝突或外鍵錯誤：{e}")
                return False
            except Exception as e:
                logger.error(f"儲存失敗：{e}")
                return False

    def save_websites_batch(self, websites: List[Website], certificate_name: Optional[str] = None) -> int:
        saved = 0
        for w in websites:
            if self.save_website(w, certificate_name):
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
