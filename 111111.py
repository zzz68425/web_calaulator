import dns.resolver

def analyze_zone_delegation(domain):
    print(f"\n{'='*50}")
    print(f"🎯 開始分析網域: {domain}")
    print(f"{'='*50}")

    # 第一步：查詢 NS 紀錄 (找出是誰負責回答這個網域的問題)
    print("[1] 查詢 NS 紀錄 (負責的 DNS 伺服器) ...")
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        for rdata in ns_answers:
            print(f"    ✅ NS: {rdata.target.to_text()}")
    except dns.resolver.NoAnswer:
        print("    ❌ 找不到 NS: 這個節點沒有獨立的名稱伺服器 (依附在上層)。")
    except dns.resolver.NXDOMAIN:
        print("    ❌ NXDOMAIN: 網域根本不存在！")
        return # 網域不存在就不用繼續查 SOA 了
    except Exception as e:
        print(f"    ⚠️ NS 查詢發生錯誤: {e}")

    print("-" * 50)

    # 第二步：查詢 SOA 紀錄 (驗證這個網域是否為獨立的管轄區 Zone)
    print("[2] 查詢 SOA 紀錄 (獨立管理權限) ...")
    try:
        soa_answers = dns.resolver.resolve(domain, 'SOA')
        for rdata in soa_answers:
            print("    ✅ 找到獨立 SOA！(這是一個獨立授權的 Zone)")
            print(f"       - 主伺服器 (MNAME) : {rdata.mname.to_text()}")
            print(f"       - 管理信箱 (RNAME) : {rdata.rname.to_text()}")
            print(f"       - 區域版本 (SERIAL): {rdata.serial}")
    except dns.resolver.NoAnswer:
        print("    ❌ 找不到 SOA: 存在但沒有獨立管理權限 (與上層共用 SOA)。")
    except Exception as e:
        print(f"    ⚠️ SOA 查詢發生錯誤: {e}")

if __name__ == "__main__":
    # 使用我們討論過的三個經典案例進行測試
    test_domains = [
        "ncku.edu.tw",          # 總公司 (區域頂點)
        "ee.ncku.edu.tw",       # 分公司 (獨立授權的子網域)
        "bbs.ccns.ncku.edu.tw"  # 普通員工 (沒有獨立授權的主機)
    ]

    for d in test_domains:
        analyze_zone_delegation(d)