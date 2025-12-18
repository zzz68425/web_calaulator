"""
資料庫管理模組（新版三表設計）
"""
import sqlite3
from typing import List, Optional, Tuple
from datetime import datetime
from models.website import Website
from utils.logger import get_logger

logger = get_logger("database.manager")


class DatabaseManager:
    """資料庫管理器（fqdn / ip / certificate）"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_database()

    def _init_database(self) -> None:
        """初始化資料庫（三表結構）"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")

            # ip 表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip (
                    id      INTEGER NOT NULL PRIMARY KEY,
                    address TEXT    NOT NULL UNIQUE,
                    type    TEXT    NOT NULL
                );
            """)

            # certificate 表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificate (
                    id   INTEGER NOT NULL PRIMARY KEY,
                    name TEXT    NOT NULL UNIQUE
                );
            """)

            # host 表（指向 ip.id 與可選的 certificate.id）
            conn.execute("""
                CREATE TABLE IF NOT EXISTS host (
                    id             INTEGER NOT NULL PRIMARY KEY,
                    name           TEXT    NOT NULL UNIQUE,
                    ip_id          INTEGER NOT NULL REFERENCES ip(id),
                    certificate_id INTEGER REFERENCES certificate(id),
                    when_crawled   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 索引
            conn.execute("CREATE INDEX IF NOT EXISTS idx_host_name ON host(name);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_host_ip_id ON host(ip_id);")
            conn.commit()
            logger.info(f"資料庫初始化完成（三表）：{self.db_path}")

    # ---------------------- 基礎 get-or-create ----------------------

    def _get_or_create_ip(self, conn: sqlite3.Connection, address: str) -> int:
        """回傳 ip.id；不存在則建立。type 由位址判斷 IPv4/IPv6。"""
        ip_type = "IPv6" if ":" in address else "IPv4"
        cur = conn.cursor()
        cur.execute("SELECT id FROM ip WHERE address = ?", (address,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO ip (address, type) VALUES (?, ?)", (address, ip_type))
        conn.commit()
        return cur.lastrowid

    def _get_or_create_certificate(self, conn: sqlite3.Connection, cert_name: Optional[str]) -> Optional[int]:
        """回傳 certificate.id；若 cert_name 為 None/空字串，回傳 None。"""
        if not cert_name:
            return None
        cur = conn.cursor()
        cur.execute("SELECT id FROM certificate WHERE name = ?", (cert_name,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO certificate (name) VALUES (?)", (cert_name,))
        conn.commit()
        return cur.lastrowid

    # ---------------------- 對外 API ----------------------

    def save_website(self, website: Website, certificate_name: Optional[str] = None) -> bool:
        """
        儲存單一網站到 host / ip / certificate。
        注意：不寫入 HTTP title / 狀態碼（已從 schema 移除）。
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                ip_id = self._get_or_create_ip(conn, website.ip)
                cert_id = self._get_or_create_certificate(conn, certificate_name)

                # INSERT OR REPLACE 以 host.name 為唯一鍵更新對應 ip_id / cert_id / when_crawled
                conn.execute(
                    """
                    INSERT INTO host (name, ip_id, certificate_id, when_crawled)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        ip_id = excluded.ip_id,
                        certificate_id = COALESCE(excluded.certificate_id, host.certificate_id),
                        when_crawled = excluded.when_crawled
                    """,
                    (website.fqdn, ip_id, cert_id, website.when_crawled),
                )
                conn.commit()
                logger.info(f"已儲存：{website.fqdn} -> IP[{website.ip}] cert={certificate_name or '-'}")
                return True
        except sqlite3.Error as e:
            logger.error(f"儲存失敗：{e}")
            return False

    def save_websites_batch(self, websites: List[Website], certificate_name: Optional[str] = None) -> int:
        """批次儲存（同一批次可共用同一張證書名）。"""
        saved = 0
        for w in websites:
            if self.save_website(w, certificate_name=certificate_name):
                saved += 1
        return saved

    def get_website_by_fqdn(self, fqdn: str) -> Optional[Website]:
        """
        以 host.name 查詢，回傳 Website（只帶 fqdn 與 ip 位址）。
        其餘欄位（url/title/status/redirect）不再入庫，這裡設為 None。
        """
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT h.leftmost_label, i.address, h.when_crawled
                FROM domain h
                JOIN ip i ON i.id = h.ip_id
                WHERE h.leftmost_label = ?
                """,
                (fqdn,),
            )
            row = cur.fetchone()
            if row:
                return Website(
                    fqdn=row[0],
                    ip=row[1],
                    url=None,
                    protocol=None,
                    status_code=None,
                    redirect_to=None,
                    title=None,
                    when_crawled=datetime.fromisoformat(row[2]) if isinstance(row[2], str) else row[2],
                )
        return None

    def get_statistics(self) -> Tuple[int, int]:
        """回傳（host 總數, 不重複 IP 數）"""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM domain;")
            total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT ip_id) FROM domain;")
            uniq_ip = cur.fetchone()[0]
            return total, uniq_ip

    def check_schema(self) -> List[Tuple]:
        """檢查三表 schema（回傳 domain/ip/certificate 的 table_info 合併）。"""
        rows: List[Tuple] = []
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            for t in ("ip", "certificate", "domain"):
                cur.execute(f"PRAGMA table_info({t});")
                rows.extend(cur.fetchall())
        return rows
