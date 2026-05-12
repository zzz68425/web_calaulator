#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析找不到域名記錄的原因
"""

import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_domain_lookup_issues():
    """分析域名查詢失敗的原因"""
    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    
    print("=== 分析「找不到域名記錄」的可能原因 ===\n")
    
    # 1. 檢查資料庫中的實際數據
    print("1. 資料庫基本統計:")
    stats = cursor.execute("""
        SELECT 
            'domain' as table_name, COUNT(*) as count
        FROM domain
        UNION ALL
        SELECT 'ip', COUNT(*) FROM ip
        UNION ALL
        SELECT 'domain_ip', COUNT(*) FROM domain_ip
        UNION ALL
        SELECT 'root_domain', COUNT(*) FROM root_domain
    """).fetchall()
    
    for table, count in stats:
        print(f"  {table}: {count} 筆記錄")
    
    # 2. 檢查具體的目標域名是否存在
    print("\n2. 檢查目標域名是否存在於資料庫:")
    target_domains = [
        'www.cans.ee.ncku.edu.tw',
        'tej.lib.ncku.edu.tw', 
        'adrc.hosp.ncku.edu.tw'
    ]
    
    for target in target_domains:
        print(f"\n  查詢: {target}")
        
        # 檢查平鋪存法記錄
        subdomain_part = target.replace('.ncku.edu.tw', '')
        flat_result = cursor.execute("""
            SELECT d.id, d.leftmost_label, d.parent_domain_id, d.root_id
            FROM domain d
            WHERE d.leftmost_label = ?
        """, (subdomain_part,)).fetchall()
        
        if flat_result:
            for record in flat_result:
                print(f"    ✅ 找到平鋪記錄: ID={record[0]}, label='{record[1]}', parent_id={record[2]}, root_id={record[3]}")
        else:
            print(f"    ❌ 沒有找到平鋪記錄: '{subdomain_part}'")
        
        # 檢查階層存法記錄
        parts = target.split('.')
        print(f"    階層查詢 {parts}:")
        for i, part in enumerate(parts):
            matches = cursor.execute("""
                SELECT id, leftmost_label, parent_domain_id, root_id
                FROM domain 
                WHERE leftmost_label = ?
            """, (part,)).fetchall()
            print(f"      '{part}': {len(matches)} 個匹配")
    
    # 3. 檢查domain_ip關聯是否存在
    print("\n3. 檢查domain_ip關聯:")
    domain_ip_stats = cursor.execute("""
        SELECT d.leftmost_label, COUNT(di.ip_id) as ip_count
        FROM domain d
        LEFT JOIN domain_ip di ON d.id = di.domain_id
        WHERE d.leftmost_label IN ('www.cans.ee', 'tej.lib', 'adrc.hosp')
        GROUP BY d.id, d.leftmost_label
    """).fetchall()
    
    for label, ip_count in domain_ip_stats:
        print(f"  '{label}': {ip_count} 個IP關聯")
    
    # 4. 檢查可能的數據不一致問題
    print("\n4. 檢查數據一致性問題:")
    
    # 檢查孤兒domain記錄（沒有IP關聯的）
    orphan_domains = cursor.execute("""
        SELECT COUNT(*) 
        FROM domain d
        WHERE d.id NOT IN (SELECT DISTINCT domain_id FROM domain_ip WHERE domain_id IS NOT NULL)
    """).fetchone()[0]
    print(f"  沒有IP關聯的domain記錄: {orphan_domains} 個")
    
    # 檢查孤兒IP記錄
    orphan_ips = cursor.execute("""
        SELECT COUNT(*) 
        FROM ip i
        WHERE i.id NOT IN (SELECT DISTINCT ip_id FROM domain_ip WHERE ip_id IS NOT NULL)
    """).fetchone()[0]
    print(f"  沒有domain關聯的IP記錄: {orphan_ips} 個")
    
    # 檢查root_id為NULL的記錄
    null_root_domains = cursor.execute("""
        SELECT id, leftmost_label, parent_domain_id
        FROM domain 
        WHERE root_id IS NULL
        ORDER BY id
    """).fetchall()
    print(f"  root_id為NULL的domain記錄: {len(null_root_domains)} 個")
    for record in null_root_domains:
        print(f"    ID={record[0]}: '{record[1]}' (parent_id={record[2]})")
    
    # 5. 模擬查詢過程
    print("\n5. 模擬repository查詢過程:")
    
    target_fqdn = 'www.cans.ee.ncku.edu.tw'
    print(f"  模擬查詢: {target_fqdn}")
    
    # 模擬平鋪存法查詢
    print("  a) 平鋪存法查詢:")
    subdomain = 'www.cans.ee'
    flat_query = cursor.execute("""
        SELECT d.id, d.leftmost_label, d.parent_domain_id, d.root_id,
               rd.name as root_name
        FROM domain d
        LEFT JOIN root_domain rd ON d.root_id = rd.id
        WHERE d.leftmost_label = ?
    """, (subdomain,)).fetchall()
    
    if flat_query:
        for record in flat_query:
            print(f"     ✅ 找到: ID={record[0]}, root='{record[4]}'")
            
            # 檢查是否有IP關聯
            ip_relations = cursor.execute("""
                SELECT di.ip_id, i.ipv4, i.ipv6
                FROM domain_ip di
                JOIN ip i ON di.ip_id = i.id
                WHERE di.domain_id = ?
            """, (record[0],)).fetchall()
            
            print(f"     IP關聯: {len(ip_relations)} 個")
            for ip_rel in ip_relations[:3]:  # 只顯示前3個
                ip_addr = ip_rel[1] or ip_rel[2] or "無IP"
                print(f"       IP: {ip_addr}")
    else:
        print(f"     ❌ 平鋪查詢失敗")
    
    # 6. 檢查save_website邏輯可能的問題
    print("\n6. 可能的save_website問題:")
    print("  - website資料沒有正確傳入")
    print("  - IP解析失敗") 
    print("  - domain記錄創建失敗")
    print("  - domain_ip關聯創建失敗")
    print("  - 事務rollback")
    print("  - 資料庫鎖定問題")
    
    conn.close()

if __name__ == "__main__":
    analyze_domain_lookup_issues()