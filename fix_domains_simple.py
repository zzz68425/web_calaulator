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
        # 1. 修復root_id
        logger.info("修復domain記錄的root_id...")
        
        root_id = cursor.execute("SELECT id FROM root_domain WHERE name = 'ncku.edu.tw'").fetchone()
        if not root_id:
            logger.error("找不到ncku.edu.tw的root_domain記錄")
            return
        root_id = root_id[0]
        
        # 更新所有屬於ncku.edu.tw但root_id為NULL的記錄
        cursor.execute("UPDATE domain SET root_id = ? WHERE root_id IS NULL AND id != 1 AND id != 2", (root_id,))
        updated_count = cursor.rowcount
        logger.info(f"修復了 {updated_count} 個domain記錄的root_id")
        
        # 2. 查找並轉換www.cans.ee.ncku.edu.tw為平鋪存法
        logger.info("轉換www.cans.ee.ncku.edu.tw為平鋪存法...")
        
        # 找到ncku域名的ID (作為新的parent)
        ncku_id = cursor.execute("SELECT id FROM domain WHERE leftmost_label = 'ncku'").fetchone()
        if not ncku_id:
            logger.error("找不到ncku域名記錄")
            return
        ncku_id = ncku_id[0]
        
        # 檢查是否已有www.cans.ee的平鋪記錄
        existing_flat = cursor.execute(
            "SELECT id FROM domain WHERE leftmost_label = 'www.cans.ee' AND parent_domain_id = ?",
            (ncku_id,)
        ).fetchone()
        
        if existing_flat:
            logger.info(f"已存在www.cans.ee的平鋪記錄 (ID: {existing_flat[0]})")
        else:
            # 找到現有的www記錄（指向cans的那個）
            www_cans_record = cursor.execute("""
                SELECT d.id 
                FROM domain d
                JOIN domain p ON d.parent_domain_id = p.id
                WHERE d.leftmost_label = 'www' AND p.leftmost_label = 'cans'
            """).fetchone()
            
            if www_cans_record:
                www_id = www_cans_record[0]
                
                # 更新為平鋪存法
                cursor.execute(
                    "UPDATE domain SET leftmost_label = ?, parent_domain_id = ?, root_id = ? WHERE id = ?",
                    ('www.cans.ee', ncku_id, root_id, www_id)
                )
                logger.info(f"成功轉換www記錄 (ID: {www_id}) 為平鋪存法")
                
                # 移除不需要的中間層記錄
                # 注意：這裡要小心，只移除沒有其他用途的記錄
            else:
                # 創建新的平鋪記錄
                cursor.execute(
                    "INSERT INTO domain (leftmost_label, parent_domain_id, root_id) VALUES (?, ?, ?)",
                    ('www.cans.ee', ncku_id, root_id)
                )
                new_id = cursor.lastrowid
                logger.info(f"創建新的平鋪記錄: www.cans.ee (ID: {new_id})")
        
        # 3. 同樣處理其他目標域名
        target_conversions = [
            ('tej.lib', 'tej', 'lib'),
            ('adrc.hosp', 'adrc', 'hosp')
        ]
        
        for flat_label, child_label, parent_label in target_conversions:
            logger.info(f"處理 {flat_label}...")
            
            # 找到現有記錄
            existing = cursor.execute("""
                SELECT d.id 
                FROM domain d
                JOIN domain p ON d.parent_domain_id = p.id
                WHERE d.leftmost_label = ? AND p.leftmost_label = ?
            """, (child_label, parent_label)).fetchone()
            
            if existing:
                cursor.execute(
                    "UPDATE domain SET leftmost_label = ?, parent_domain_id = ? WHERE id = ?",
                    (flat_label, ncku_id, existing[0])
                )
                logger.info(f"轉換 {child_label}.{parent_label} -> {flat_label} (ID: {existing[0]})")
        
        conn.commit()
        
        # 4. 驗證結果
        logger.info("驗證修復結果...")
        
        test_records = cursor.execute("""
            SELECT d.leftmost_label, d.parent_domain_id, pd.leftmost_label as parent_label
            FROM domain d
            JOIN domain pd ON d.parent_domain_id = pd.id
            WHERE d.leftmost_label IN ('www.cans.ee', 'tej.lib', 'adrc.hosp')
        """).fetchall()
        
        for record in test_records:
            logger.info(f"平鋪記錄: '{record[0]}' -> parent: '{record[2]}' (ID: {record[1]})")
        
        # 統計
        total_domains = cursor.execute("SELECT COUNT(*) FROM domain").fetchone()[0]
        null_root_count = cursor.execute("SELECT COUNT(*) FROM domain WHERE root_id IS NULL").fetchone()[0]
        
        logger.info(f"修復完成 - 總域名: {total_domains}, root_id為NULL: {null_root_count}")
        
    except Exception as e:
        logger.error(f"修復過程中發生錯誤: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    fix_domain_records()