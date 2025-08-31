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
                    sn      INTEGER NOT NULL PRIMARY KEY,
                    address TEXT    NOT NULL UNIQUE,
                    type    TEXT    NOT NULL
                );
            """)

            # certificate 表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificate (
                    sn   INTEGER NOT NULL PRIMARY KEY,
                    name TEXT    NOT NULL UNIQUE
                );
            """)

            # fqdn 表（指向 ip.sn 與可選的 certificate.sn）
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fqdn (
                    sn             INTEGER NOT NULL PRIMARY KEY,
                    name           TEXT    NOT NULL UNIQUE,
                    ip_sn          INTEGER NOT NULL REFERENCES ip(sn),
                    certificate_sn INTEGER REFERENCES certificate(sn),
                    when_crawled   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 索引
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fqdn_name ON fqdn(name);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fqdn_ip_sn ON fqdn(ip_sn);")
            conn.commit()
            logger.info(f"資料庫初始化完成（三表）：{self.db_path}")

    # ---------------------- 基礎 get-or-create ----------------------

    def _get_or_create_ip(self, conn: sqlite3.Connection, address: str) -> int:
        """回傳 ip.sn；不存在則建立。type 由位址判斷 IPv4/IPv6。"""
        ip_type = "IPv6" if ":" in address else "IPv4"
        cur = conn.cursor()
        cur.execute("SELECT sn FROM ip WHERE address = ?", (address,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO ip (address, type) VALUES (?, ?)", (address, ip_type))
        conn.commit()
        return cur.lastrowid

    def _get_or_create_certificate(self, conn: sqlite3.Connection, cert_name: Optional[str]) -> Optional[int]:
        """回傳 certificate.sn；若 cert_name 為 None/空字串，回傳 None。"""
        if not cert_name:
            return None
        cur = conn.cursor()
        cur.execute("SELECT sn FROM certificate WHERE name = ?", (cert_name,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO certificate (name) VALUES (?)", (cert_name,))
        conn.commit()
        return cur.lastrowid

    # ---------------------- 對外 API ----------------------

    def save_website(self, website: Website, certificate_name: Optional[str] = None) -> bool:
        """
        儲存單一網站到 fqdn / ip / certificate。
        注意：不寫入 HTTP title / 狀態碼（已從 schema 移除）。
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                ip_sn = self._get_or_create_ip(conn, website.ip)
                cert_sn = self._get_or_create_certificate(conn, certificate_name)

                # INSERT OR REPLACE 以 fqdn.name 為唯一鍵更新對應 ip_sn / cert_sn / when_crawled
                conn.execute(
                    """
                    INSERT INTO fqdn (name, ip_sn, certificate_sn, when_crawled)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        ip_sn = excluded.ip_sn,
                        certificate_sn = COALESCE(excluded.certificate_sn, fqdn.certificate_sn),
                        when_crawled = excluded.when_crawled
                    """,
                    (website.fqdn, ip_sn, cert_sn, website.when_crawled),
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
        以 fqdn.name 查詢，回傳 Website（只帶 fqdn 與 ip 位址）。
        其餘欄位（url/title/status/redirect）不再入庫，這裡設為 None。
        """
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT f.name, i.address, f.when_crawled
                FROM fqdn f
                JOIN ip i ON i.sn = f.ip_sn
                WHERE f.name = ?
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
        """回傳（fqdn 總數, 不重複 IP 數）"""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM fqdn;")
            total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT ip_sn) FROM fqdn;")
            uniq_ip = cur.fetchone()[0]
            return total, uniq_ip

    def check_schema(self) -> List[Tuple]:
        """檢查三表 schema（回傳 fqdn/ip/certificate 的 table_info 合併）。"""
        rows: List[Tuple] = []
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            for t in ("ip", "certificate", "fqdn"):
                cur.execute(f"PRAGMA table_info({t});")
                rows.extend(cur.fetchall())
        return rows
