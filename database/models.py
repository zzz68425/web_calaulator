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

class Certificate(Base):
    __tablename__ = "certificate"

    sn: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    fqdns: Mapped[list["Fqdn"]] = relationship("Fqdn", back_populates="certificate")

    def __repr__(self) -> str:
        return f"<Cert sn={self.sn} {self.name}>"

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
    certificate_sn: Mapped[int | None] = mapped_column(ForeignKey("certificate.sn", ondelete="SET NULL"))
    when_crawled: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.current_timestamp())

    ip: Mapped["IP"] = relationship("IP", back_populates="fqdns")
    certificate: Mapped["Certificate"] = relationship("Certificate", back_populates="fqdns")

    def __repr__(self) -> str:
        return f"<Fqdn sn={self.sn} {self.name} -> ip_sn={self.ip_sn} cert_sn={self.certificate_sn}>"