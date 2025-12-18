#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
域名階層處理模組
用於解析 FQDN 並建立正確的階層結構（階層式存法）
"""

import logging
from typing import Dict, List, Set, Optional, Tuple
from database.models import Domain
from database.session import db_session
from database.repository import DatabaseManagerORM
from sqlalchemy import select

logger = logging.getLogger(__name__)


class DomainHierarchyBuilder:
    """
    域名階層建構器
    負責解析完整域名並建立階層關係（階層式存法）
    
    例如：health.mdic.ncku.edu.tw 會分解為：
    - tw (parent: NULL)
    - edu (parent: tw)
    - ncku (parent: edu)
    - mdic (parent: ncku)
    - health (parent: mdic)
    """
    
    def __init__(self, db_manager: DatabaseManagerORM):
        self.db_manager = db_manager
        
    def build_domain_hierarchy_from_fqdns(self, all_fqdns: List[str], root_domains: List[str]) -> Dict[str, int]:
        """
        為給定的 FQDN 列表建立域名階層
        
        Args:
            all_fqdns: 所有完整域名列表（包含根域名和子域名）
            root_domains: 根域名列表（從步驟1 Shodan獲得）
            
        Returns:
            建立的域名映射 {fqdn: domain_id}
        """
        logger.info(f"開始建立域名階層（階層式）：{len(all_fqdns)} 個域名，{len(root_domains)} 個根域名")
        
        domain_id_map = {}
        
        with db_session(self.db_manager.SessionFactory) as session:
            # 第一步：處理所有根域名的階層分解
            for root_domain in root_domains:
                logger.info(f"處理根域名階層：{root_domain}")
                root_hierarchy = self._build_domain_hierarchy(session, root_domain, root_domain)
                domain_id_map.update(root_hierarchy)
            
            # 第二步：處理所有子域名（階層式存法）
            for fqdn in all_fqdns:
                if fqdn in domain_id_map:
                    # 已經處理過，跳過
                    continue
                    
                # 找出這個 FQDN 對應的根域名
                matching_root = self._find_matching_root_domain(fqdn, root_domains)
                if not matching_root:
                    logger.warning(f"無法找到 {fqdn} 對應的根域名，跳過")
                    continue
                
                # 建立子域名記錄（階層式）
                subdomain_hierarchy = self._build_domain_hierarchy(session, fqdn, matching_root)
                domain_id_map.update(subdomain_hierarchy)
                    
            session.commit()
        
        logger.info(f"域名階層建立完成，處理了 {len(domain_id_map)} 個域名")
        return domain_id_map
    
    def _build_domain_hierarchy(self, session, fqdn: str, root_domain: str) -> Dict[str, int]:
        """
        建立域名的階層結構（階層式存法）
        例如：health.mdic.ncku.edu.tw -> 
            tw(parent: NULL) -> edu(parent: tw) -> ncku(parent: edu) -> mdic(parent: ncku) -> health(parent: mdic)
        
        Args:
            session: 資料庫 session
            fqdn: 完整域名
            root_domain: 此 FQDN 對應的根域名
        
        Returns:
            {domain_string: domain_id} 映射
        """
        parts = fqdn.split('.')
        parts.reverse()  # ['tw', 'edu', 'ncku', 'mdic', 'health']
        
        hierarchy_map = {}
        parent_id = None
        
        # 獲取或創建 root_domain 記錄
        root_domain_record = self.db_manager.get_or_create_root_domain(root_domain)
        
        # 從右到左建立階層（tw -> edu -> ncku -> mdic -> health）
        current_domain_parts = []
        for i, part in enumerate(parts):
            current_domain_parts.append(part)
            current_domain_str = '.'.join(reversed(current_domain_parts))
            
            # 檢查是否已存在
            existing = session.execute(
                select(Domain).where(
                    Domain.leftmost_label == part,
                    Domain.parent_domain_id == parent_id
                )
            ).scalar_one_or_none()
            
            if existing:
                hierarchy_map[current_domain_str] = existing.id
                parent_id = existing.id
                logger.debug(f"域名層級已存在: {current_domain_str} (ID: {existing.id})")
            else:
                # 判斷是否要設定 root_id
                # 只有當此層級屬於根域名或子域名時才設定 root_id
                should_set_root_id = (current_domain_str == root_domain or 
                                      current_domain_str.endswith('.' + root_domain) or
                                      root_domain.endswith('.' + current_domain_str))
                
                # 創建新的域名記錄
                new_domain = Domain(
                    leftmost_label=part,
                    parent_domain_id=parent_id,
                    root_id=root_domain_record.id if should_set_root_id else None
                )
                session.add(new_domain)
                session.flush()
                hierarchy_map[current_domain_str] = new_domain.id
                parent_id = new_domain.id
                logger.info(f"創建域名層級: {current_domain_str} (ID: {new_domain.id}, parent: {new_domain.parent_domain_id}, root_id: {new_domain.root_id})")
        
        return hierarchy_map
    
    def _find_matching_root_domain(self, fqdn: str, root_domains: List[str]) -> Optional[str]:
        """
        找出 FQDN 對應的根域名
        例如：n8n.course.aislab.ee.nptu.edu.tw -> nptu.edu.tw
        """
        for root in root_domains:
            if fqdn.endswith('.' + root) or fqdn == root:
                return root
        return None


def build_domain_hierarchy(db_manager: DatabaseManagerORM, all_fqdns: List[str], root_domains: List[str]) -> Dict[str, int]:
    """
    便利函數：建立域名階層
    
    Args:
        db_manager: 資料庫管理器
        all_fqdns: 所有完整域名列表
        root_domains: 根域名列表
        
    Returns:
        域名到ID的映射
    """
    builder = DomainHierarchyBuilder(db_manager)
    return builder.build_domain_hierarchy_from_fqdns(all_fqdns, root_domains)