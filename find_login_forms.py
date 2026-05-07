"""搜尋有帳號密碼表單的頁面"""
import sqlite3
import re
from collections import Counter

conn = sqlite3.connect('website.db')
cursor = conn.cursor()

# 搜尋 Body 欄位，並取得 Title
cursor.execute('''
    WITH RECURSIVE domain_path AS (
        SELECT id, leftmost_label, parent_domain_id, leftmost_label as full_path
        FROM domain WHERE parent_domain_id IS NULL
        UNION ALL
        SELECT d.id, d.leftmost_label, d.parent_domain_id, d.leftmost_label || '.' || dp.full_path
        FROM domain d JOIN domain_path dp ON d.parent_domain_id = dp.id
    )
    SELECT dp.full_path as fqdn, o.name, o.value,
           (SELECT o2.value FROM otx_httpscan o2 
            JOIN domain d2 ON o2.domain_id = d2.id
            WHERE d2.id = dp.id AND o2.name LIKE '%Title%' LIMIT 1) as title
    FROM otx_httpscan o JOIN domain_path dp ON o.domain_id = dp.id 
    WHERE o.name LIKE '%Body%'
''')

results = cursor.fetchall()

print('=' * 80)
print('搜尋有帳號密碼表單的頁面')
print('=' * 80)

# 搜尋密碼欄位特徵（去重）
password_forms = {}
for fqdn, name, body, title in results:
    body_lower = body.lower()
    
    # 檢查 <input type="password"> 密碼輸入欄位
    if re.search(r'type\s*=\s*["\']?password', body_lower):
        if fqdn not in password_forms:
            password_forms[fqdn] = {
                'title': title or '(no title)',
                'ports': set(),
                'reasons': set()
            }
        
        # 從 name 提取 port (如 '443 Body' -> 443)
        port = name.split()[0] if name else ''
        password_forms[fqdn]['ports'].add(port)
        password_forms[fqdn]['reasons'].add('input type=password')
        
        # 額外檢查
        if re.search(r'(name|id)\s*=\s*["\']?password', body_lower):
            password_forms[fqdn]['reasons'].add('name/id=password')

print(f'\n找到 {len(password_forms)} 個有帳號密碼表單的頁面\n')

print('[詳細列表]')
print('-' * 60)
for fqdn in sorted(password_forms.keys()):
    info = password_forms[fqdn]
    ports = ', '.join(sorted(info['ports']))
    reasons = ', '.join(sorted(info['reasons']))
    print(f'{fqdn}')
    print(f'  Title: {info["title"][:60]}')
    print(f'  Ports: {ports}')
    print(f'  特徵: {reasons}')
    print()

conn.close()
