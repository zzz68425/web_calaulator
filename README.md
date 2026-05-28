---
id: A12-2025-006
authors:
  - 張弘頎
contributors:
  - 黃頎洲
collaborators:
tags:
  - otx
  - python
  - shodan
created_date: 2026-01-19
updated_date: 2026-01-21
---

# Educational Domain Inventory Tool (EDIT)

本專案旨在透過第三方被動式偵察服務，全自動化盤點特定根網域於廣域網路的公開子網域，協助教育部建立公開網域資產清冊。

透過整合 [LevelBlue Open Threat Exchange](https://otx.alienvault.com/) 和 [Shodan Search Engine](https://www.shodan.io/) 等外部偵察資料，得評估網站弱點掃描服務之覆蓋率，以落實攻擊面管理，並提升網域資產的可視性。

## 專案目標

網站弱點掃描服務的挑戰在於**未知網域資產**，故本專案預期提供以下管理價值：

1. 界定掃描範圍：依據根網域自動搜尋公開子網域。
2. 評估績效指標：協助計算網站弱點掃描比例，量化掃描覆蓋績效。
3. 追蹤動態資產：定期同步外部情資，及時更新網域資產資料庫。

## 實作原理

本專案高度依賴第三方被動式偵察服務，確保以不干擾學術網路運作為前提，收錄網域資產：

1. 驗證存活服務 (Shodan)：利用 Shodan 搜尋引擎驗證該網域當前是否具有開放之 Web 服務（HTTP/HTTPS），過濾掉失效的紀錄。
2. 歷史解析溯源 (OTX)：調閱 AlienVault OTX 累積之 DNS 歷史紀錄，找出所有曾指向教育體系 IP 的子網域。
3. 彙整資產清單：系統將自動比對現有掃描排程，標註出「尚未納入弱點掃描」之資產。

## 使用方式

1. 安裝 Git 版本控制軟體
2. 安裝 uv 套件管理軟體
3. 複製 GitLab 儲存庫
4. 在terminal輸入
```bash
uv sync
```
5. 複製 .env.example 為 .env
6. 取得各網站的 API Key 並貼到 .env，並將 DNS_SERVERS 設為 8.8.8.8
7. 在terminal輸入
```bash
uv run main.py
```
8. 在憑證模式輸入欲查詢的根網域，例如*.ncku.edu.tw，若要進行全部.edu的查詢則輸入*.edu.tw。
9. 選擇查詢模式，若要匯入教育部整理出的現有教育單位請選擇1(若要進行全部.edu的查詢推薦輸入1)，若只是要搜尋某根網域下的所有子網域請選擇2