# database/models.py
from __future__ import annotations
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, Index, func
)
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column
from datetime import datetime

Base = declarative_base()

class IP(Base):
    __tablename__ = "ip"

    sn: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    address: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)  # IPv4 / IPv6

    # 反向關聯
    fqdns: Mapped[list["Fqdn"]] = relationship("Fqdn", back_populates="ip", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<IP sn={self.sn} {self.address} ({self.type})>"

class RootDomain(Base):
    __tablename__ = "root_domain"

    sn: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    fqdns: Mapped[list["Fqdn"]] = relationship("Fqdn", back_populates="root_domain")

    def __repr__(self) -> str:
        return f"<RootDomain sn={self.sn} {self.name}>"

class Fqdn(Base):
    __tablename__ = "fqdn"
    __table_args__ = (
        UniqueConstraint("name", name="uq_fqdn_name"),
        Index("idx_fqdn_name", "name"),
        Index("idx_fqdn_ip_sn", "ip_sn"),
    )

    sn: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    ip_sn: Mapped[int] = mapped_column(ForeignKey("ip.sn", ondelete="RESTRICT"), nullable=False)
    root_sn: Mapped[int | None] = mapped_column(ForeignKey("root_domain.sn", ondelete="SET NULL"))
    when_crawled: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())

    ip: Mapped["IP"] = relationship("IP", back_populates="fqdns")
    root_domain: Mapped["RootDomain"] = relationship("RootDomain", back_populates="fqdns")  

    def __repr__(self) -> str:
        return f"<Fqdn sn={self.sn} {self.name} -> ip_sn={self.ip_sn} root_sn={self.root_sn}>"


class Institution(Base):
    __tablename__ = "institution"
    __table_args__ = (
        UniqueConstraint("domain", name="uq_institution_domain"),
        Index("idx_institution_domain", "domain"),
    )

    sn: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    domain: Mapped[str] = mapped_column(String, nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"<Institution sn={self.sn} name={self.name} domain={self.domain}>"