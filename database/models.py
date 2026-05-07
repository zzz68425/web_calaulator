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
        UniqueConstraint("address", name="uq_ip_address"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    address: Mapped[str] = mapped_column(String, nullable=False)  # 單一 IP 欄位（可存 IPv4 或 IPv6）

    # 多對多關聯到 Domain
    domains: Mapped[list["Domain"]] = relationship("Domain", secondary="domain_ip", back_populates="ips")
    
    # Domain_ip 關聯
    domain_ips: Mapped[list["Domain_ip"]] = relationship("Domain_ip", back_populates="ip", cascade="all, delete-orphan", overlaps="domains")

    def __repr__(self) -> str:
        return f"<IP id={self.id} address={self.address}>"

class RootDomain(Base):
    __tablename__ = "root_domain"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    source: Mapped[str | None] = mapped_column(String, nullable=True)  # 'shodan' / 'xlsx' / None

    domains: Mapped[list["Domain"]] = relationship("Domain", back_populates="root_domain")

    def __repr__(self) -> str:
        return f"<RootDomain id={self.id} {self.name} source={self.source}>"

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
    type: Mapped[str | None] = mapped_column(String, nullable=True)  # IoT 設備類型：Synology NAS, Embedded Web Server, Login Form 等
    a: Mapped[int | None] = mapped_column(Integer, nullable=True)      # A 紀錄存在 = 1
    aaaa: Mapped[int | None] = mapped_column(Integer, nullable=True)   # AAAA 紀錄存在 = 1
    cname: Mapped[int | None] = mapped_column(Integer, nullable=True)  # CNAME 紀錄存在 = 1

    # 多對多關聯到 IP
    ips: Mapped[list["IP"]] = relationship("IP", secondary="domain_ip", back_populates="domains", overlaps="domain_ips")
    root_domain: Mapped["RootDomain"] = relationship("RootDomain", back_populates="domains")
    parent_domain: Mapped["Domain"] = relationship("Domain", remote_side=[id], back_populates="child_domains")
    child_domains: Mapped[list["Domain"]] = relationship("Domain", back_populates="parent_domain")
    
    # Domain_ip 關聯
    domain_ips: Mapped[list["Domain_ip"]] = relationship("Domain_ip", back_populates="domain", cascade="all, delete-orphan", overlaps="ips,domains")

    # DNS Zone 關聯
    dns_zone_links: Mapped[list["Domain_dns_zone"]] = relationship("Domain_dns_zone", back_populates="domain", cascade="all, delete-orphan")

    # otx_httpscan 關聯（一對多）
    otx_httpscans: Mapped[list["Otx_httpscan"]] = relationship("Otx_httpscan", back_populates="domain", cascade="all, delete-orphan")
    
    # shodan_http 關聯（一對多）
    shodan_https: Mapped[list["Shodan_http"]] = relationship("Shodan_http", back_populates="domain", cascade="all, delete-orphan")
    
    # shodan_product 關聯（一對多）
    shodan_products: Mapped[list["Shodan_product"]] = relationship("Shodan_product", back_populates="domain", cascade="all, delete-orphan")

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


class Dns_zone(Base):
    __tablename__ = "dns_zone"
    __table_args__ = (
        UniqueConstraint("zone_apex", name="uq_dns_zone_apex"),
        Index("idx_dns_zone_apex", "zone_apex"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    zone_apex: Mapped[str] = mapped_column(String, nullable=False)

    soa_mname: Mapped[str | None] = mapped_column(String, nullable=True)
    soa_rname: Mapped[str | None] = mapped_column(String, nullable=True)
    soa_serial: Mapped[int | None] = mapped_column(Integer, nullable=True)
    soa_refresh: Mapped[int | None] = mapped_column(Integer, nullable=True)
    soa_retry: Mapped[int | None] = mapped_column(Integer, nullable=True)
    soa_expire: Mapped[int | None] = mapped_column(Integer, nullable=True)
    soa_minimum: Mapped[int | None] = mapped_column(Integer, nullable=True)
    soa_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)

    status: Mapped[str] = mapped_column(String, nullable=False, default="ok")
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp(), onupdate=func.current_timestamp())

    ns_records: Mapped[list["Dns_zone_ns"]] = relationship("Dns_zone_ns", back_populates="zone", cascade="all, delete-orphan")
    domain_links: Mapped[list["Domain_dns_zone"]] = relationship("Domain_dns_zone", back_populates="zone", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Dns_zone id={self.id} zone_apex={self.zone_apex} status={self.status}>"


class Dns_zone_ns(Base):
    __tablename__ = "dns_zone_ns"
    __table_args__ = (
        UniqueConstraint("zone_id", "ns_host", name="uq_dns_zone_ns"),
        Index("idx_dns_zone_ns_zone_id", "zone_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("dns_zone.id", ondelete="CASCADE"), nullable=False)
    ns_host: Mapped[str] = mapped_column(String, nullable=False)
    ns_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())

    zone: Mapped["Dns_zone"] = relationship("Dns_zone", back_populates="ns_records")

    def __repr__(self) -> str:
        return f"<Dns_zone_ns id={self.id} zone_id={self.zone_id} ns_host={self.ns_host}>"


class Domain_dns_zone(Base):
    __tablename__ = "domain_dns_zone"
    __table_args__ = (
        UniqueConstraint("domain_id", "zone_id", name="uq_domain_dns_zone"),
        Index("idx_domain_dns_zone_domain_id", "domain_id"),
        Index("idx_domain_dns_zone_zone_id", "zone_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domain.id", ondelete="CASCADE"), nullable=False)
    zone_id: Mapped[int] = mapped_column(ForeignKey("dns_zone.id", ondelete="CASCADE"), nullable=False)
    matched_by: Mapped[str | None] = mapped_column(String, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())

    domain: Mapped["Domain"] = relationship("Domain", back_populates="dns_zone_links")
    zone: Mapped["Dns_zone"] = relationship("Dns_zone", back_populates="domain_links")

    def __repr__(self) -> str:
        return f"<Domain_dns_zone id={self.id} domain_id={self.domain_id} zone_id={self.zone_id}>"

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


class Shodan_http(Base):
    __tablename__ = "shodan_http"
    __table_args__ = (
        Index("idx_shodan_http_domain_id", "domain_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domain.id", ondelete="CASCADE"), nullable=False)
    html: Mapped[str] = mapped_column(String, nullable=True)  # Shodan http.html 內容

    # 關聯到 Domain（多對一）
    domain: Mapped["Domain"] = relationship("Domain", back_populates="shodan_https")

    def __repr__(self) -> str:
        return f"<Shodan_http id={self.id} domain_id={self.domain_id}>"


class Shodan_product(Base):
    __tablename__ = "shodan_product"
    __table_args__ = (
        Index("idx_shodan_product_domain_id", "domain_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domain.id", ondelete="CASCADE"), nullable=False)
    product: Mapped[str] = mapped_column(String, nullable=True)  # Shodan product 欄位內容

    # 關聯到 Domain（多對一）
    domain: Mapped["Domain"] = relationship("Domain", back_populates="shodan_products")

    def __repr__(self) -> str:
        return f"<Shodan_product id={self.id} domain_id={self.domain_id} product={self.product}>"
