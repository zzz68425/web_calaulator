#!/usr/bin/env python3
"""
為 uv 專案建立 __init__.py 檔案（簡單匯入版本）
執行方式: python create_init_files.py
"""
import os
import sys
from pathlib import Path

def detect_project_structure():
    """偵測專案結構（src layout 或 flat layout）"""
    if os.path.exists('src'):
        return 'src/website_finder'
    elif os.path.exists('website_finder'):
        return 'website_finder'
    else:
        # 詢問使用者
        print("找不到 website_finder 目錄")
        print("請選擇專案結構：")
        print("1. src/website_finder (src layout)")
        print("2. website_finder (flat layout)")
        choice = input("選擇 (1 或 2): ").strip()
        
        if choice == '1':
            return 'src/website_finder'
        else:
            return 'website_finder'

# __init__.py 檔案內容（簡單匯入版本）
init_files = {
    '__init__.py': '''"""Website Finder - Shodan + VirusTotal 網站發現工具"""
from .main import WebsiteFinder
from .config import Config
''',
    
    'models/__init__.py': '''"""資料模型"""
from .website import Website, ShodanResult
''',
    
    'database/__init__.py': '''"""資料庫管理"""
from .manager import DatabaseManager
''',
    
    'scanners/__init__.py': '''"""掃描器模組"""
from .shodan_scanner import ShodanScanner
from .virustotal_scanner import VirusTotalScanner
''',
    
    'validators/__init__.py': '''"""驗證器模組"""
from .website_validator import WebsiteValidator
''',
    
    'utils/__init__.py': '''"""工具函數"""
from .converters import IPConverter
from .network import rate_limit
'''
}

def create_init_files(base_path):
    """建立所有 __init__.py 檔案"""
    created_files = []
    
    for relative_path, content in init_files.items():
        full_path = os.path.join(base_path, relative_path)
        
        # 建立目錄（如果不存在）
        directory = os.path.dirname(full_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            print(f"📁 建立目錄: {directory}")
        
        # 寫入 __init__.py
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ 建立: {full_path}")
        created_files.append(full_path)
    
    return created_files

def update_pyproject_toml(package_path):
    """更新 pyproject.toml（如果需要）"""
    pyproject_path = Path('pyproject.toml')
    
    if not pyproject_path.exists():
        print("\n⚠️  找不到 pyproject.toml")
        return
    
    print("\n📝 pyproject.toml 建議設定：")
    
    if 'src/' in package_path:
        packages_config = '[tool.uv.sources]\npackages = [{include = "website_finder", from = "src"}]'
    else:
        packages_config = '[tool.uv.sources]\npackages = [{include = "website_finder"}]'
    
    print(f"""
請確認 pyproject.toml 包含以下設定：

[project]
name = "website-finder"
version = "1.0.0"
dependencies = [
    "shodan>=1.28.0",
    "requests>=2.28.0", 
    "dnspython>=2.3.0",
]

{packages_config}
""")

def create_module_stubs(base_path):
    """建立模組檔案的空白模板（如果不存在）"""
    module_files = {
        'main.py': '"""主程式入口"""\n# TODO: 複製 main.py 程式碼到這裡\n',
        'config.py': '"""配置管理"""\n# TODO: 複製 config.py 程式碼到這裡\n',
        'models/website.py': '"""網站資料模型"""\n# TODO: 複製 website.py 程式碼到這裡\n',
        'database/manager.py': '"""資料庫管理器"""\n# TODO: 複製 manager.py 程式碼到這裡\n',
        'scanners/base.py': '"""掃描器基礎類別"""\n# TODO: 複製 base.py 程式碼到這裡\n',
        'scanners/shodan_scanner.py': '"""Shodan 掃描器"""\n# TODO: 複製 shodan_scanner.py 程式碼到這裡\n',
        'scanners/virustotal_scanner.py': '"""VirusTotal 掃描器"""\n# TODO: 複製 virustotal_scanner.py 程式碼到這裡\n',
        'validators/website_validator.py': '"""網站驗證器"""\n# TODO: 複製 website_validator.py 程式碼到這裡\n',
        'utils/converters.py': '"""轉換工具"""\n# TODO: 複製 converters.py 程式碼到這裡\n',
        'utils/network.py': '"""網路工具"""\n# TODO: 複製 network.py 程式碼到這裡\n',
    }
    
    print("\n📄 建立模組檔案模板...")
    for relative_path, content in module_files.items():
        full_path = os.path.join(base_path, relative_path)
        
        # 只在檔案不存在時建立
        if not os.path.exists(full_path):
            directory = os.path.dirname(full_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
            
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"📝 建立模板: {full_path}")
        else:
            print(f"⏭️  跳過（已存在）: {full_path}")

def main():
    """主函數"""
    print("=" * 60)
    print("🚀 為 uv 專案建立 Website Finder 結構")
    print("=" * 60)
    
    # 偵測或選擇專案結構
    package_path = detect_project_structure()
    print(f"\n📦 使用套件路徑: {package_path}")
    
    # 建立套件目錄（如果不存在）
    if not os.path.exists(package_path):
        os.makedirs(package_path)
        print(f"📁 建立套件目錄: {package_path}")
    
    # 建立 __init__.py 檔案
    print("\n🔨 建立 __init__.py 檔案...")
    created_files = create_init_files(package_path)
    
    # 建立模組檔案模板
    create_module_stubs(package_path)
    
    # 更新 pyproject.toml 建議
    update_pyproject_toml(package_path)
    
    # 顯示結果
    print("\n" + "=" * 60)
    print("✨ 完成！")
    print("=" * 60)
    
    # 顯示目錄結構
    print(f"\n📁 建立的結構 ({package_path}):")
    for root, dirs, files in os.walk(package_path):
        level = root.replace(package_path, '').count(os.sep)
        indent = '  ' * level
        print(f'{indent}{os.path.basename(root)}/')
        subindent = '  ' * (level + 1)
        for file in files:
            print(f'{subindent}{file}')
    
    print("\n📋 下一步：")
    print("1. 將之前提供的模組程式碼複製到對應的 .py 檔案")
    print("2. 使用 uv 安裝依賴:")
    print("   uv add shodan requests dnspython")
    print("3. 設定 API Keys:")
    print("   export SHODAN_API_KEY='your_key'")
    print("   export VIRUSTOTAL_API_KEY='your_key'")
    print("4. 執行程式:")
    print(f"   uv run python -m website_finder.main '*.example.edu.tw'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  使用者中斷")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 錯誤: {e}", file=sys.stderr)
        sys.exit(1)