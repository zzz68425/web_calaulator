#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修復域名記錄並轉換為平鋪存法
"""

import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_domain_records():
    """修復域名記錄問題"""
    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    
    try:
        # 1. 首先修復所有domain記錄的root_id
        logger.info("修復domain記錄的root_id...")
        
        # 獲取ncku.edu.tw的root_id
        root_id = cursor.execute("SELECT id FROM root_domain WHERE name = 'ncku.edu.tw'").fetchone()
        if not root_id:
            logger.error("找不到ncku.edu.tw的root_domain記錄")
            return
        root_id = root_id[0]
        
        # 更新所有屬於ncku.edu.tw的domain記錄的root_id
        cursor.execute("""
            UPDATE domain 
            SET root_id = ? 
            WHERE root_id IS NULL 
            AND id IN (
                SELECT DISTINCT d.id 
                FROM domain d
                WHERE d.id = 3 OR -- ncku本身
                      d.parent_domain_id = 3 OR -- ncku的直接子域名
                      d.parent_domain_id IN (SELECT id FROM domain WHERE parent_domain_id = 3) OR -- 第三層
                      d.parent_domain_id IN (SELECT id FROM domain WHERE parent_domain_id IN (SELECT id FROM domain WHERE parent_domain_id = 3)) -- 更深層
            )
        """, (root_id,))
        
        updated_count = cursor.rowcount
        logger.info(f"修復了 {updated_count} 個domain記錄的root_id")
        
        # 2. 轉換為平鋪存法
        logger.info("開始轉換為平鋪存法...")
        
        # 獲取所有需要轉換的多級域名（3級以上的）
        complex_domains = cursor.execute("""
            WITH RECURSIVE domain_path AS (
                -- 基礎案例：找出所有最深層的域名（沒有子域名的）
                SELECT d.id, d.leftmost_label, d.parent_domain_id, 
                       d.leftmost_label as full_path, 1 as level
                FROM domain d
                WHERE d.id NOT IN (SELECT DISTINCT parent_domain_id FROM domain WHERE parent_domain_id IS NOT NULL)
                  AND d.parent_domain_id IS NOT NULL
                
                UNION ALL
                
                -- 遞歸案例：往上追溯父域名
                SELECT p.id, p.leftmost_label, p.parent_domain_id,
                       dp.full_path || '.' || p.leftmost_label, dp.level + 1
                FROM domain p
                INNER JOIN domain_path dp ON p.id = dp.parent_domain_id
                WHERE p.parent_domain_id IS NOT NULL
            )
            SELECT dp.full_path, dp.level, dp.id
            FROM domain_path dp
            WHERE dp.level >= 3  -- 3級以上的域名（如www.cans.ee）
            AND dp.full_path LIKE '%.%.%'  -- 確保有多個點
            ORDER BY dp.level DESC, dp.full_path
        """).fetchall()
        
        logger.info(f"發現 {len(complex_domains)} 個需要轉換的多級域名")
        
        conversions = []
        for full_path, level, domain_id in complex_domains:
            # 分析域名結構
            if '.ncku.edu.tw' in full_path:
                # 提取子域名部分和目標父域名
                subdomain_part = full_path.replace('.ncku.edu.tw', '')
                target_parent = 'ncku.edu.tw'
                
                # 獲取目標父域名的ID
                parent_result = cursor.execute(
                    "SELECT id FROM domain WHERE leftmost_label = 'ncku' AND parent_domain_id = (SELECT id FROM domain WHERE leftmost_label = 'edu')"
                ).fetchone()
                
                if parent_result:
                    target_parent_id = parent_result[0]
                    conversions.append((subdomain_part, target_parent_id, domain_id, full_path))\n                    \n        logger.info(f\"準備轉換 {len(conversions)} 個域名為平鋪存法\")\n        \n        # 執行轉換\n        converted_count = 0\n        for subdomain_part, target_parent_id, old_domain_id, full_path in conversions:\n            try:\n                # 檢查是否已經存在平鋪存法的記錄\n                existing = cursor.execute(\n                    \"SELECT id FROM domain WHERE leftmost_label = ? AND parent_domain_id = ?\",\n                    (subdomain_part, target_parent_id)\n                ).fetchone()\n                \n                if existing:\n                    # 如果已存在，更新所有指向舊記錄的關聯\n                    cursor.execute(\n                        \"UPDATE domain_ip SET domain_id = ? WHERE domain_id = ?\",\n                        (existing[0], old_domain_id)\n                    )\n                    \n                    # 刪除舊記錄\n                    cursor.execute(\"DELETE FROM domain WHERE id = ?\", (old_domain_id,))\n                    logger.info(f\"合併域名: {full_path} -> 使用現有記錄 ID {existing[0]}\")\n                else:\n                    # 直接更新現有記錄為平鋪存法\n                    cursor.execute(\n                        \"UPDATE domain SET leftmost_label = ?, parent_domain_id = ?, root_id = ? WHERE id = ?\",\n                        (subdomain_part, target_parent_id, root_id, old_domain_id)\n                    )\n                    logger.info(f\"轉換域名: {full_path} -> leftmost='{subdomain_part}', parent_id={target_parent_id}\")\n                \n                converted_count += 1\n                \n            except Exception as e:\n                logger.error(f\"轉換域名 {full_path} 時發生錯誤: {e}\")\n        \n        # 3. 清理孤兒記錄\n        logger.info(\"清理孤兒記錄...\")\n        orphan_count = cursor.execute(\"\"\"\n            DELETE FROM domain \n            WHERE id NOT IN (SELECT DISTINCT parent_domain_id FROM domain WHERE parent_domain_id IS NOT NULL)\n            AND id NOT IN (SELECT DISTINCT domain_id FROM domain_ip)\n            AND parent_domain_id IS NOT NULL\n            AND id NOT IN (3, 6, 21, 56)  -- 保留重要的域名記錄\n        \"\"\").rowcount\n        \n        logger.info(f\"清理了 {orphan_count} 個孤兒記錄\")\n        \n        # 提交所有更改\n        conn.commit()\n        \n        logger.info(f\"域名修復完成：轉換了 {converted_count} 個域名，更新了 {updated_count} 個root_id\")\n        \n        # 4. 驗證結果\n        logger.info(\"驗證修復結果...\")\n        \n        # 檢查www.cans.ee.ncku.edu.tw是否正確\n        www_cans_ee = cursor.execute(\"\"\"\n            SELECT d.id, d.leftmost_label, d.parent_domain_id, d.root_id,\n                   pd.leftmost_label as parent_label\n            FROM domain d\n            LEFT JOIN domain pd ON d.parent_domain_id = pd.id\n            WHERE d.leftmost_label = 'www.cans.ee'\n        \"\"\").fetchone()\n        \n        if www_cans_ee:\n            logger.info(f\"找到平鋪存法記錄: ID {www_cans_ee[0]}, leftmost='{www_cans_ee[1]}', parent_id={www_cans_ee[2]}, parent_label='{www_cans_ee[4]}'\")\n        else:\n            logger.warning(\"未找到 www.cans.ee 的平鋪存法記錄\")\n        \n        # 統計最終狀態\n        total_domains = cursor.execute(\"SELECT COUNT(*) FROM domain\").fetchone()[0]\n        null_root_count = cursor.execute(\"SELECT COUNT(*) FROM domain WHERE root_id IS NULL\").fetchone()[0]\n        \n        logger.info(f\"最終統計: 總域名 {total_domains}, root_id為NULL的域名 {null_root_count}\")\n        \n    except Exception as e:\n        logger.error(f\"修復過程中發生錯誤: {e}\")\n        conn.rollback()\n        raise\n    finally:\n        conn.close()\n\nif __name__ == \"__main__\":\n    fix_domain_records()