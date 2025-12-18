# database/models.py
from __future__ import annotations
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, Index, func, event, DDL
)
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column
from datetime import datetime

Base = declarative_base()

# 定義 FQDN 視圖
fqdn_view_ddl = DDL("""
    CREATE VIEW IF NOT EXISTS fqdn AS
    WITH RECURSIVE
        cte AS (
            SELECT
                id,
                leftmost_label || '.' AS name,
                parent_domain_id,
                parent_domain_id AS current_parent_domain_id
            FROM domain
            UNION ALL
            SELECT
                cte.id,
                cte.name || domain.leftmost_label || '.' AS name,
                cte.parent_domain_id,
                domain.parent_domain_id AS current_parent_domain_id
            FROM domain
                JOIN cte ON cte.current_parent_domain_id = domain.id
        )
    SELECT id, name, parent_domain_id
    FROM cte
    WHERE
        current_parent_domain_id IS NULL;
""")

event.listen(Base.metadata, 'after_create', fqdn_view_ddl)

class IP(Base):
    __tablename__ = "ip"
    __table_args__ = (
        UniqueConstraint("ipv4", "ipv6", name="uq_ip_combination"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ipv4: Mapped[str | None] = mapped_column(String)  # IPv4（移除 unique 約束）
    ipv6: Mapped[str | None] = mapped_column(String)  # IPv6（移除 unique 約束）

    # 多對多關聯到 Domain
    domains: Mapped[list["Domain"]] = relationship("Domain", secondary="domain_ip", back_populates="ips")
    
    # Domain_ip 關聯
    domain_ips: Mapped[list["Domain_ip"]] = relationship("Domain_ip", back_populates="ip", cascade="all, delete-orphan", overlaps="domains")

    def __repr__(self) -> str:
        return f"<IP id={self.id} ipv4={self.ipv4} ipv6={self.ipv6}>"

class RootDomain(Base):
    __tablename__ = "root_domain"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    domains: Mapped[list["Domain"]] = relationship("Domain", back_populates="root_domain")

    def __repr__(self) -> str:
        return f"<RootDomain id={self.id} {self.name}>"

class Domain(Base):
    __tablename__ = "domain"
    __table_args__ = (
        UniqueConstraint("leftmost_label", "parent_domain_id", name="uq_domain_label_parent"),
        Index("idx_domain_leftmost_label", "leftmost_label"),
        Index("idx_domain_parent_id", "parent_domain_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    leftmost_label: Mapped[str] = mapped_column(String, nullable=False)
    root_id: Mapped[int | None] = mapped_column(ForeignKey("root_domain.id", ondelete="SET NULL"))
    parent_domain_id: Mapped[int | None] = mapped_column(ForeignKey("domain.id", ondelete="SET NULL"), nullable=True)
    when_crawled: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())
    when_latest_otx_checked: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    when_latest_certificate_checked: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 多對多關聯到 IP
    ips: Mapped[list["IP"]] = relationship("IP", secondary="domain_ip", back_populates="domains", overlaps="domain_ips")
    root_domain: Mapped["RootDomain"] = relationship("RootDomain", back_populates="domains")
    parent_domain: Mapped["Domain"] = relationship("Domain", remote_side=[id], back_populates="child_domains")
    child_domains: Mapped[list["Domain"]] = relationship("Domain", back_populates="parent_domain")
    
    # Domain_ip 關聯
    domain_ips: Mapped[list["Domain_ip"]] = relationship("Domain_ip", back_populates="domain", cascade="all, delete-orphan", overlaps="ips,domains")

    # otx_httpscan 關聯（一對多）
    otx_httpscans: Mapped[list["Otx_httpscan"]] = relationship("Otx_httpscan", back_populates="domain", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Domain id={self.id} {self.leftmost_label} -> root_id={self.root_id} parent_id={self.parent_domain_id}>"


class Area(Base):
    __tablename__ = "area"
    __table_args__ = (
        UniqueConstraint("domain", name="uq_area_domain"),
        Index("idx_area_domain", "domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    domain: Mapped[str] = mapped_column(String, nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"<Area id={self.id} name={self.name} domain={self.domain}>"
    
    
class Domain_ip(Base):
    __tablename__ = "domain_ip"
    __table_args__ = (
        UniqueConstraint("domain_id", "ip_id", name="uq_domain_ip_combination"),
        Index("idx_domain_ip_domain_id", "domain_id"),
        Index("idx_domain_ip_ip_id", "ip_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domain.id", ondelete="CASCADE"), nullable=False)
    ip_id: Mapped[int] = mapped_column(ForeignKey("ip.id", ondelete="CASCADE"), nullable=False)
    
    # 關聯關係
    domain: Mapped["Domain"] = relationship("Domain", back_populates="domain_ips", overlaps="domains,ips")
    ip: Mapped["IP"] = relationship("IP", back_populates="domain_ips", overlaps="domains,ips")

    def __repr__(self) -> str:
        return f"<Domain_ip id={self.id} domain_id={self.domain_id} ip_id={self.ip_id}>"

class Otx_httpscan(Base):
    __tablename__ = "otx_httpscan"
    __table_args__ = (
        Index("idx_otx_httpscan_domain_id", "domain_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # 一個 domain_id 可對應多筆 httpscan 資料（一對多）
    domain_id: Mapped[int] = mapped_column(ForeignKey("domain.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)   # 如 "80 Body", "443 Header"
    value: Mapped[str] = mapped_column(String, nullable=False)  # 掃描結果值

    # 關聯到 Domain（多對一）
    domain: Mapped["Domain"] = relationship("Domain", back_populates="otx_httpscans")

    def __repr__(self) -> str:
        return f"<Otx_httpscan id={self.id} domain_id={self.domain_id} name={self.name}>"
