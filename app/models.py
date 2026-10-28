from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_url: Mapped[str] = mapped_column(String(300), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dependencies: Mapped[list["DependencyRecord"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class DependencyRecord(Base):
    __tablename__ = "dependencies"
    __table_args__ = (UniqueConstraint("scan_id", "name", "version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(250))
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scan: Mapped[Scan] = relationship(back_populates="dependencies")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="dependency", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id", ondelete="CASCADE"), index=True)
    osv_id: Mapped[str] = mapped_column(String(100), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str | None] = mapped_column(String(30), nullable=True)
    dependency: Mapped[DependencyRecord] = relationship(back_populates="vulnerabilities")
