import sys
import json
from typing import Set, List
from datetime import datetime

import requests
from sqlalchemy import select

from config import Config
from database.session import create_session_factory, db_session
from database.models import Base, Certificate

CRTJSON_URL = "https://crt.sh/json?cn=ncku.edu.tw&exclude=expired"
TIMEOUT = 30
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/58.0.3029.110 Safari/537.36"
)


def fetch_crtsh_json(url: str = CRTJSON_URL, timeout: int = TIMEOUT) -> List[dict]:
    headers = {"User-Agent": UA}
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def extract_names(records: List[dict]) -> Set[str]:
    names: Set[str] = set()
    for item in records:
        # name_value 可能是多行（以 \n 分隔），每行是一個名稱
        nv = item.get("name_value")
        if not nv:
            continue
        # 保留原樣寫入（含萬用字元、子網域），僅做 strip 與去重
        for part in str(nv).split("\n"):
            name = part.strip()
            if name:
                names.add(name)
    return names


def ensure_schema(engine) -> None:
    # 確保 certificate 資料表存在
    Base.metadata.create_all(engine)


def insert_cert_names(names: Set[str]) -> tuple[int, int]:
    engine, SessionFactory = create_session_factory(Config.DATABASE_PATH)
    ensure_schema(engine)

    inserted = 0
    skipped = 0
    with db_session(SessionFactory) as session:
        for name in sorted(names):
            exists = session.execute(
                select(Certificate).where(Certificate.name == name)
            ).scalar_one_or_none()
            if exists:
                skipped += 1
                continue
            session.add(Certificate(name=name))
            inserted += 1
    return inserted, skipped


def main() -> int:
    print(f"[crt.sh] Query: {CRTJSON_URL}", file=sys.stderr)
    try:
        records = fetch_crtsh_json()
    except requests.exceptions.RequestException as e:
        print(f"[error] request failed: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("[error] invalid JSON response", file=sys.stderr)
        return 3

    names = extract_names(records)
    print(f"[crt.sh] extracted names: {len(names)}", file=sys.stderr)

    inserted, skipped = insert_cert_names(names)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"[db] {ts} certificate insert={inserted} skip(exists)={skipped}",
        file=sys.stderr,
    )

    # 也將結果輸出到 stdout 方便檢視
    out = {
        "count": len(names),
        "inserted": inserted,
        "skipped": skipped,
        "sample": sorted(list(names))[:20],
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
