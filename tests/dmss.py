import dns.resolver

def verify_domain_alive(domain):
    print(f"正在驗證: {domain} ...")
    
    # 定義我們要檢查的紀錄類型清單
    record_types = ['A', 'AAAA', 'CNAME']
    found_records = []

    try:
        # 依序檢查每種紀錄
        for qtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, qtype)
                for rdata in answers:
                    found_records.append(f"[{qtype}] {rdata}")
            except dns.resolver.NoAnswer:
                # 找不到這種紀錄是正常的，繼續找下一種
                continue
                
        # 判斷結果
        if found_records:
            print(f"[+] 網域存活！找到以下紀錄：")
            for record in found_records:
                print(f"    -> {record}")
            return True
        else:
            print(f"[-] 網域存在，但沒有 A、AAAA 或 CNAME 紀錄 (可能是純 MX 或 TXT 網域)。")
            return False

    except dns.resolver.NXDOMAIN:
        # 這是最明確的結果：網域已經被徹底刪除或根本不存在
        print(f"[x] 結論：網域已不存在 (NXDOMAIN)。")
        return False
        
    except dns.resolver.Timeout:
        print(f"[!] 查詢超時，DNS 伺服器沒有回應。")
        return False
        
    except Exception as e:
        print(f"[!] 發生未預期的錯誤: {e}")
        return False

if __name__ == "__main__":
    # 測試名單 (包含常見網域與絕對不存在的網域)
    test_list = [
        "ncku.edu.tw",              # 會有 A 和 AAAA
        "bbs.ccns.ncku.edu.tw",          # 通常會有 CNAME
        "ee.ncku.edu.tw",         # 可能有 A 或 CNAME
        "bd000.web3.ncku.edu.tw",     # 可能有 A 或 CNAME
        "thisdomaindoesnotexist12345.ncku.edu.tw",  # 絕對不存在
    ]

    for d in test_list:
        verify_domain_alive(d)
        print("-" * 40)