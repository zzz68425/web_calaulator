# database/session.py
from __future__ import annotations
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

def make_sqlite_url(db_path: str) -> str:
    # SQLite 本機檔案
    return f"sqlite:///{db_path}"

def create_session_factory(db_path: str):
    engine = create_engine(
        make_sqlite_url(db_path),
        echo=False,                # 需要除錯可設 True
        future=True
    )
    SessionFactory = scoped_session(
        sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    )
    return engine, SessionFactory

@contextmanager
def db_session(SessionFactory):
    """用 with 管理交易，發生例外會自動 rollback。"""
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()