#!/usr/bin/env python3
import sqlite3

def debug_domain_records():
    """調試域名記錄問題"""
    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    
    # 1. 檢查所有root_domain記錄
    print("=== ROOT DOMAIN 記錄 ===")
    root_domains = cursor.execute("SELECT id, name FROM root_domain ORDER BY id").fetchall()
    for rid, name in root_domains:
        print(f"Root ID {rid}: {name}")
    
    print("\n=== DOMAIN 記錄統計 ===")
    # 2. 檢查domain記錄的root_id分布
    root_id_stats = cursor.execute("""
        SELECT root_id, COUNT(*) as count 
        FROM domain 
        GROUP BY root_id 
        ORDER BY root_id
    """).fetchall()
    
    for root_id, count in root_id_stats:
        root_name = "NULL" if root_id is None else dict(root_domains).get(root_id, "UNKNOWN")
        print(f"Root ID {root_id} ({root_name}): {count} domains")
    
    # 3. 檢查具體的domain記錄
    print(f"\n=== 前20個DOMAIN記錄詳情 ===")
    domains = cursor.execute("""
        SELECT d.id, d.leftmost_label, d.root_id, d.parent_domain_id,
               rd.name as root_name
        FROM domain d
        LEFT JOIN root_domain rd ON d.root_id = rd.id
        ORDER BY d.id
        LIMIT 20
    """).fetchall()
    
    for domain in domains:
        did, label, root_id, parent_id, root_name = domain
        print(f"ID {did}: '{label}' | root_id={root_id}({root_name}) | parent_id={parent_id}")
    
    # 4. 檢查沒有root_id的domain記錄
    print(f"\n=== 沒有ROOT_ID的DOMAIN記錄 ===")
    no_root_domains = cursor.execute("""
        SELECT id, leftmost_label, parent_domain_id
        FROM domain 
        WHERE root_id IS NULL
        ORDER BY id
        LIMIT 10
    """).fetchall()
    
    for did, label, parent_id in no_root_domains:
        print(f"ID {did}: '{label}' | parent_id={parent_id} | NO ROOT_ID")
    
    # 5. 構建一些完整FQDN來看看問題
    print(f"\n=== 嘗試構建FQDN（檢查問題）===")
    
    def get_domain_fqdn(domain_id, cache=None):
        if cache is None:
            cache = {}
        
        if domain_id in cache:
            return cache[domain_id]
        
        result = cursor.execute(
            "SELECT leftmost_label, parent_domain_id, root_id FROM domain WHERE id = ?", 
            (domain_id,)
        ).fetchone()
        
        if not result:
            return None
            
        leftmost_label, parent_id, root_id = result
        
        if parent_id is None:
            # 這是根域名層級，查詢root_domain表
            if root_id:
                root_name = cursor.execute(
                    "SELECT name FROM root_domain WHERE id = ?", 
                    (root_id,)
                ).fetchone()
                fqdn = root_name[0] if root_name else leftmost_label
            else:
                fqdn = leftmost_label
        else:
            parent_fqdn = get_domain_fqdn(parent_id, cache)
            if parent_fqdn:
                fqdn = f"{leftmost_label}.{parent_fqdn}"
            else:
                fqdn = leftmost_label
        
        cache[domain_id] = fqdn
        return fqdn
    
    # 檢查一些特定的domain記錄
    test_domains = cursor.execute("""
        SELECT id, leftmost_label, parent_domain_id, root_id
        FROM domain 
        WHERE leftmost_label IN ('www', 'cans', 'ee', 'ncku', 'adrc', 'tej', 'lib', 'hosp')
        ORDER BY leftmost_label, id
    """).fetchall()
    
    cache = {}
    for did, label, parent_id, root_id in test_domains:
        fqdn = get_domain_fqdn(did, cache)
        print(f"'{label}' (ID {did}) -> FQDN: {fqdn}")
    
    # 6. 查看repository中找不到域名的可能原因
    print(f"\n=== 檢查查詢邏輯問題 ===")
    
    # 模擬查詢 'www.cans.ee.ncku.edu.tw'
    target_fqdn = 'www.cans.ee.ncku.edu.tw'
    print(f"嘗試查詢: {target_fqdn}")
    
    # 檢查是否有直接匹配的記錄（平鋪存法）
    flat_match = cursor.execute("""
        SELECT d.id, d.leftmost_label, d.parent_domain_id, rd.name as root_name
        FROM domain d
        LEFT JOIN root_domain rd ON d.root_id = rd.id
        WHERE d.leftmost_label = 'www.cans.ee'
    """).fetchall()
    
    if flat_match:
        print(f"找到平鋪存法記錄: {flat_match}")
    else:
        print("沒有找到平鋪存法記錄")
    
    # 檢查分層存法的記錄
    hierarchical_parts = ['www', 'cans', 'ee', 'ncku']
    for part in hierarchical_parts:
        matches = cursor.execute("""
            SELECT d.id, d.leftmost_label, d.parent_domain_id, rd.name as root_name
            FROM domain d
            LEFT JOIN root_domain rd ON d.root_id = rd.id
            WHERE d.leftmost_label = ?
        """, (part,)).fetchall()
        
        print(f"'{part}' 部分的記錄: {len(matches)} 個")
        for match in matches[:3]:  # 只顯示前3個
            print(f"  ID {match[0]}: parent_id={match[2]}, root={match[3]}")
    
    conn.close()

if __name__ == "__main__":
    debug_domain_records()