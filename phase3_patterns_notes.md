# Phase 3 Patterns Notes (Protocol-Specific Fuzzing)

## 1) Overview

Phase 3 的目的：在 Phase 1 的語法（STX/LEN/CMD/PAYLOAD/CHECKSUM/ETX）與 Phase 2 的完全隨機 byte 序列之後，使用「已知常見醫療/串口協定 framing 與 prefix」來生成測試向量，增加命中真協定 framing 的機率。Phase 3 透過固定前導/結尾 pattern（例如 STX/ETX、SOH/ETX、AA55、SLIP 0xC0 等）加上短 payload 探測裝置反應。此 phase 只做 framing/prefix 的排列與 payload 混合（隨機+結構），沒有額外 checksum/BCC/CRC 計算。實作入口為 `fuzz_phase3_protocol_specific`，並用 `test_phase="phase3_protocol"` 標記到 `commands.json` 與 report 分類。Phase 3 的 coverage 是以固定 pattern 清單為主，可透過 `_custom_patterns` 擴充。 

Phase 3 的執行策略要點：
- 每個 pattern 會測 `data_len=0..min(max_payload_len,8)`，每個長度再發送 1..10 次（依 `tests_per_pattern` 計算）。
- payload 的 30% 會走 `_generate_structured_payload`（含常見常數與可能的長度欄位），70% 走完全隨機。


核心差異：
- Phase 1：boofuzz grammar 以 `[STX][LEN][CMD][PAYLOAD][CHECKSUM][ETX]` 做組合 fuzz（具 checksum）。
- Phase 2：完全隨機 byte 序列。
- Phase 3：固定 prefix/suffix + 短 payload (0..min(max_payload_len, 8))。

## 2) Pattern Catalog（總表）

> 生成長度規則：`data_len` 取 `range(0, min(max_payload_len + 1, 9))`，所以 payload 最長 8 bytes。總長度 = len(prefix) + data_len + len(suffix)。

| Pattern 名稱 | Byte Layout | 最小/最大長度 | 產生邏輯 | 可能的協定意涵 | 程式碼定位 |
| --- | --- | --- | --- | --- | --- |
| STX + CMD + ETX | [02][DATA...][03] | 2 / 10 | 固定 prefix/suffix + payload 隨機或結構化 | Text framing / STX-ETX | `fuzz_phase3_protocol_specific` patterns list |
| SOH + CMD + ETX | [01][DATA...][03] | 2 / 10 | 同上 | Header-based framing | 同上 |
| CMD80 + param | [80][DATA...] | 1 / 7 | prefix + payload | Command opcode 0x80 | 同上 |
| CMD81 + param | [81][DATA...] | 1 / 7 | prefix + payload | Command opcode 0x81 | 同上 |
| CMD82 + param | [82][DATA...] | 1 / 7 | prefix + payload | Command opcode 0x82 | 同上 |
| CMD90 + param | [90][DATA...] | 1 / 7 | prefix + payload | Command opcode 0x90 | 同上 |
| CMD91 + param | [91][DATA...] | 1 / 7 | prefix + payload | Command opcode 0x91 | 同上 |
| Frame + data + 7E | [7E][DATA...][7E] | 2 / 10 | prefix/suffix 0x7E + payload | HDLC-style delimiter | 同上 |
| Sync + data | [AA][55][DATA...] | 2 / 8 | 2B sync + payload | Sync marker | 同上 |
| Marker + data | [FF][00][DATA...] | 2 / 8 | marker + payload | Marker/sentinel | 同上 |
| DLE + data + ETX | [10][DATA...][03] | 2 / 8 | prefix 0x10 + suffix 0x03 | DLE/ETX framing | 同上 |
| SLIP frame + data | [C0][DATA...][C0] | 2 / 10 | SLIP boundary + payload | SLIP-like framing | 同上 |
| ACK + data | [06][DATA...] | 1 / 5 | prefix ACK + payload | ACK/ACK-with-data | 同上 |
| NAK + data | [15][DATA...] | 1 / 5 | prefix NAK + payload | NAK / error | 同上 |
| EOT + data | [04][DATA...] | 1 / 5 | prefix EOT + payload | EOT / end-of-transmission | 同上 |
| ENQ | [05] | 1 / 1 | prefix only | ENQ / enquiry | 同上 |
| DEL frame | [7F][DATA...][7F] | 2 / 8 | delimiter 0x7F + payload | DEL-based framing | 同上 |
| Query command | [51][DATA...] | 1 / 5 | prefix 0x51 + payload | Query op | 同上 |
| Info command | [49][DATA...] | 1 / 5 | prefix 0x49 + payload | Info op | 同上 |
| Status command | [53][DATA...] | 1 / 5 | prefix 0x53 + payload | Status op | 同上 |
| CMDA0 + param | [A0][DATA...] | 1 / 7 | prefix 0xA0 + payload | vendor CMD | 同上 |
| CMDA1 + param | [A1][DATA...] | 1 / 7 | prefix 0xA1 + payload | vendor CMD | 同上 |
| CMDB0 + param | [B0][DATA...] | 1 / 7 | prefix 0xB0 + payload | vendor CMD | 同上 |
| CMDC1 + param | [C1][DATA...] | 1 / 7 | prefix 0xC1 + payload | vendor CMD | 同上 |

## 3) Deep Dive（逐一展開每個 pattern）

> Payload 生成策略（所有 pattern 共用）：
> - `data_len=0` → 空 payload。
> - `data_len>0` → 70% 完全隨機 `os.urandom`，30% 使用 `_generate_structured_payload`（包含常見常數、可能的 length 值等）。

### 3.1 STX + CMD + ETX
- **原理**：STX/ETX 常見於文字/ASCII 傳輸協定中，STX=0x02 作為起始符，ETX=0x03 作為結尾；中間可放指令或 payload。
- **程式碼如何實作**（關鍵片段）：
  - `medical_patterns` 定義 `([0x02], "STX + CMD + ETX", [0x03], 8)`。
  - 送出格式：`full_cmd_bytes = bytes(prefix) + payload + bytes(suffix)`。
- **欄位拆解**：
  - [02]：固定 STX。
  - [DATA...]：0..8 bytes，可能包含命令碼/參數。
  - [03]：固定 ETX。
- **例子**：
  - `02 03` (空 payload)
  - `02 80 01 03` (payload=0x80 0x01)
- **變異建議**：
  - 固定 STX/ETX，優先掃 payload 第 1 byte（可能是 CMD）。
  - 針對長度 1..3 先做 exhaustive，觀察回應 pattern 分群。

### 3.2 SOH + CMD + ETX
- **原理**：SOH=0x01 通常表示 header 開始，配合 ETX 結束；部分簡易協定會用 SOH + data + ETX framing。
- **程式碼如何實作**：pattern `([0x01], "SOH + CMD + ETX", [0x03], 8)`。
- **欄位拆解**：[01][DATA...][03]。
- **例子**：
  - `01 03` (空 payload)
  - `01 51 00 03` (payload=0x51 0x00)
- **變異建議**：
  - 嘗試讓 payload 第 1 byte 對齊常見 cmd（0x51/0x49/0x53/0x80）。

### 3.3 CMD80 + param
- **原理**：單 byte opcode + 參數是最常見的命令格式，0x80 可能是功能碼。
- **程式碼如何實作**：pattern `([0x80], "CMD80 + param", [], 6)`。
- **欄位拆解**：[80][DATA...]。
- **例子**：
  - `80` (空 payload)
  - `80 01 00` (payload=0x01 0x00)
- **變異建議**：
  - 保持 0x80 固定，掃 payload[0]、payload[1] 作為 param/length。

### 3.4 CMD81 + param
- **原理**：同 CMD80，另一命令碼。
- **實作**：pattern `([0x81], "CMD81 + param", [], 6)`。
- **欄位拆解**：[81][DATA...]。
- **例子**：`81`, `81 FF 00`。
- **變異建議**：
  - payload 長度 1..2 先掃，觀察 response 是否有固定 header。

### 3.5 CMD82 + param
- **原理**：同 CMD80/81。
- **實作**：pattern `([0x82], "CMD82 + param", [], 6)`。
- **欄位拆解**：[82][DATA...]。
- **例子**：`82`, `82 10 03`。
- **變異建議**：
  - 搭配 prefix=0x82 固定，掃 payload[0] 0x00..0xFF。

### 3.6 CMD90 + param
- **原理**：0x90/0x91 常用為高位命令碼。
- **實作**：pattern `([0x90], "CMD90 + param", [], 6)`。
- **欄位拆解**：[90][DATA...]。
- **例子**：`90`, `90 01 02`。
- **變異建議**：
  - payload[0] 試 0x00/0x01/0xFF，觀察回應長度。

### 3.7 CMD91 + param
- **原理**：與 CMD90 類似。
- **實作**：pattern `([0x91], "CMD91 + param", [], 6)`。
- **欄位拆解**：[91][DATA...]。
- **例子**：`91`, `91 02 00`。
- **變異建議**：
  - 如果 CMD90 有回應，優先在 CMD91 上掃 1-2 bytes。

### 3.8 Frame + data + 7E
- **原理**：0x7E 是 HDLC/PPP 的常見 frame delimiter。
- **實作**：pattern `([0x7E], "Frame + data + 7E", [0x7E], 8)`。
- **欄位拆解**：[7E][DATA...][7E]。
- **例子**：`7E 7E`, `7E 01 02 7E`。
- **變異建議**：
  - 固定 7E delim，嘗試插入 0x7E 於 payload 中觀察 escaping 是否存在。

### 3.9 Sync + data (AA55)
- **原理**：AA55 常見於同步/對齊標記。
- **實作**：pattern `([0xAA, 0x55], "Sync + data", [], 6)`。
- **欄位拆解**：[AA][55][DATA...]。
- **例子**：`AA 55`, `AA 55 01 02`。
- **變異建議**：
  - 固定 AA55，掃 payload[0]，觀察回應是否含 echo。

### 3.10 Marker + data (FF00)
- **原理**：FF00 可能是 idle/marker 或特殊 header。
- **實作**：pattern `([0xFF, 0x00], "Marker + data", [], 6)`。
- **欄位拆解**：[FF][00][DATA...]。
- **例子**：`FF 00`, `FF 00 AA 55`。
- **變異建議**：
  - payload[0] 依 0x00/0xFF/0xAA/0x55 掃描。

### 3.11 DLE + data + ETX
- **原理**：DLE(0x10)+ETX 常用於 DLE-stuffing 的 framing。
- **實作**：pattern `([0x10], "DLE + data + ETX", [0x03], 6)`。
- **欄位拆解**：[10][DATA...][03]。
- **例子**：`10 03`, `10 01 02 03`。
- **變異建議**：
  - payload 中插入 0x10/0x03 觀察 escaping。

### 3.12 SLIP frame + data
- **原理**：SLIP (RFC1055) 使用 0xC0 作為 frame boundary。
- **實作**：pattern `([0xC0], "SLIP frame + data", [0xC0], 8)`。
- **欄位拆解**：[C0][DATA...][C0]。
- **例子**：`C0 C0`, `C0 00 01 C0`。
- **變異建議**：
  - payload 中插入 0xC0/0xDB，測試是否有 SLIP escaping。

### 3.13 ACK + data
- **原理**：ACK(0x06) 可能是回覆碼，也可能是命令型 ack + data。
- **實作**：pattern `([0x06], "ACK + data", [], 4)`。
- **欄位拆解**：[06][DATA...]。
- **例子**：`06`, `06 01`。
- **變異建議**：
  - 嘗試 ack + length byte（payload[0]=len）。

### 3.14 NAK + data
- **原理**：NAK(0x15) 代表否定回覆，可作為 reset/negate command。
- **實作**：pattern `([0x15], "NAK + data", [], 4)`。
- **欄位拆解**：[15][DATA...]。
- **例子**：`15`, `15 00`。
- **變異建議**：
  - 嘗試 payload=0x01/0xFF，觀察是否觸發 error reply。

### 3.15 EOT + data
- **原理**：EOT(0x04) 用於結束傳輸或 session。
- **實作**：pattern `([0x04], "EOT + data", [], 4)`。
- **欄位拆解**：[04][DATA...]。
- **例子**：`04`, `04 00`。
- **變異建議**：
  - 以單 byte EOT + 0x00/0x01 觀察是否 reset link。

### 3.16 ENQ
- **原理**：ENQ(0x05) 用於詢問/建立連線。
- **實作**：pattern `([0x05], "ENQ", [], 0)`。
- **欄位拆解**：[05]。
- **例子**：`05`, `05` (固定長度)
- **變異建議**：
  - ENQ 前後加 inter-frame delay 或重試次數，觀察回應。

### 3.17 DEL frame
- **原理**：0x7F 可能是 delimiter 或特殊 marker。
- **實作**：pattern `([0x7F], "DEL frame", [0x7F], 6)`。
- **欄位拆解**：[7F][DATA...][7F]。
- **例子**：`7F 7F`, `7F 01 02 7F`。
- **變異建議**：
  - payload 中插入 0x7F 觀察 escape。

### 3.18 Query command
- **原理**：0x51 ('Q') 可能是 query 命令（常見於血糖計）。
- **實作**：pattern `([0x51], "Query command", [], 4)`。
- **欄位拆解**：[51][DATA...]。
- **例子**：`51`, `51 00`。
- **變異建議**：
  - payload[0] 取 0x00/0x01/0x10 掃描。

### 3.19 Info command
- **原理**：0x49 ('I') 可能是 info/identify 命令。
- **實作**：pattern `([0x49], "Info command", [], 4)`。
- **欄位拆解**：[49][DATA...]。
- **例子**：`49`, `49 00`。
- **變異建議**：
  - 如果有回應，記錄回應前綴與長度。

### 3.20 Status command
- **原理**：0x53 ('S') 可能是 status 命令。
- **實作**：pattern `([0x53], "Status command", [], 4)`。
- **欄位拆解**：[53][DATA...]。
- **例子**：`53`, `53 01`。
- **變異建議**：
  - payload[0] 掃描 0x00/0x01/0xFF。

### 3.21 CMDA0 + param
- **原理**：0xA0 類 vendor-specific command。
- **實作**：pattern `([0xA0], "CMDA0 + param", [], 6)`。
- **欄位拆解**：[A0][DATA...]。
- **例子**：`A0`, `A0 01 02`。
- **變異建議**：
  - 將 payload[0] 當 subcommand 掃描。

### 3.22 CMDA1 + param
- **原理**：0xA1 vendor-specific。
- **實作**：pattern `([0xA1], "CMDA1 + param", [], 6)`。
- **欄位拆解**：[A1][DATA...]。
- **例子**：`A1`, `A1 00 01`。
- **變異建議**：
  - 如果 A0 有回應，A1 也需要測試相同 payload 組合。

### 3.23 CMDB0 + param
- **原理**：0xB0 vendor-specific。
- **實作**：pattern `([0xB0], "CMDB0 + param", [], 6)`。
- **欄位拆解**：[B0][DATA...]。
- **例子**：`B0`, `B0 10 00`。
- **變異建議**：
  - payload[0] 掃 0x00..0x0F 短掃描。

### 3.24 CMDC1 + param
- **原理**：0xC1 vendor-specific。
- **實作**：pattern `([0xC1], "CMDC1 + param", [], 6)`。
- **欄位拆解**：[C1][DATA...]。
- **例子**：`C1`, `C1 00 00`。
- **變異建議**：
  - payload[0] 先固定 0x00，再掃 payload[1]。

## 4) Success Heuristics（成功判定與回應分類）

**成功判定**：
- 只要 `read_response()` 在 timeout (2 秒) 內讀到任何 byte，即視為成功 (`response != None`)。
- `send_hex_command` 會等待 0.1s 再讀取，並將 response 直接寫入 `commands.json`。此處沒有額外的 regex/contains 或 length check。

**回應 pattern 分類**：
- `analysis_report.txt` 會將所有成功 response 中的 `HEX:` 部分當成 pattern key，印出 `Pattern 1..N`，並列出觸發該 response 的 request 清單。
- 建議將 `phase3_protocol` 的成功命令與 `Pattern N` 的 response mapping 起來，追查哪個 prefix 對應哪個 response header。

**報告中的命名與對應**：
- Phase 3 command 會以 `test_phase="phase3_protocol"` 寫入 `commands.json`，可用於過濾 Phase 3 記錄。
- 在 Phase 3 成功列表中，`pattern_name` 與 `payload_length` 被存入 `phase_successful_commands`，可作為與 response 的關聯提示。
- `analysis_report.txt` 中的推薦提示會標示 `STX/ETX framing detected` 或 `Frame delimiter (0x7E)`，是基於成功命令中的 request bytes 是否包含 `02`/`03` 或 `7E`。

## 5) Gaps & TODO

**不確定/推測點**：
1. Phase 3 沒有 checksum/BCC/CRC，若裝置需要校驗，可能全部 miss。
2. `STX + CMD + ETX` 命名暗示 CMD 但實際 payload 無固定欄位，需推斷 `payload[0]` 是否為 CMD。
3. `CMD80/82/90/91` 可能需要固定長度/子命令，現有 fuzz 只做 0..6 bytes。
4. `SLIP`/`DLE`/`7E` 可能需要 escape 規則，但 Phase 3 未做 escaping。
5. Response pattern 的分類僅依 hex 字串，不做 header/length/CRC 解碼，需手動判讀。

**5 個最小成本驗證實驗**：
1. **固定 framing 掃 CMD**：STX/ETX 下固定 payload length=1，掃 0x00..0xFF，建立 response map。
2. **長度敏感測試**：對 CMD80/CMD82 固定 payload[0]，逐一改變 payload length (1..6) 看 response length/timeout。
3. **Delimiter 逃逸測試**：在 7E/SLIP/DLE pattern 中插入 delimiter byte，觀察是否回應 error 或 escape。
4. **Marker/Sync 對齊**：AA55 與 FF00 pattern 重複發送，觀察是否需要 inter-frame delay（例如 10ms/100ms）。
5. **Response echo 檢查**：固定 payload 為已知序列 (AA 55 00 01)，看回應是否 echo 原 request 或返回 checksum，推斷是否存在 length/checksum。
