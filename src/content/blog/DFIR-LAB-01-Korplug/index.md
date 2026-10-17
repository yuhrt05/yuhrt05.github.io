---
title: "DFIR LAB 01: Korplug"
description: "Phân tích mẫu Korplug RAT: DLL side-loading, unpacking/manual mapping, persistence, process injection và liên lạc C2."
date: 2026-01-03
authors: [ane]
tags: [malware analysis, static analysis, dynamic analysis, autoruns, mitre-attack, persistence]
image: "./assets/banner.jpg"
---

## Tổng quan

| Trường thông tin | Mô tả |
| :--- | :--- |
| Tên mẫu | `McAfee.exe` |
| Phân loại | Korplug RAT (theo nhận định ban đầu) |
| Kỹ thuật nổi bật | DLL side-loading, unpacking/manual mapping, persistence, process injection |
| Thành phần | `McAfee.exe` (ứng dụng ký số bị lợi dụng), `McUtil.dll` (loader), `McUtil.dll.mc` (payload đóng gói) |
| Hành vi quan sát | Persistence, thao tác bộ nhớ, quét mạng LAN, liên lạc C2 |
| Mức độ rủi ro | Cao |
| Nền tảng | Windows |

Bài viết phân tích mẫu qua ba hướng: kiểm tra tĩnh, quan sát hành vi trong VM và debug loader để lần theo quá trình giải mã payload. Các kết luận bên dưới phân biệt hành vi quan sát trực tiếp với năng lực suy ra từ API.

## Stage 1 --- Phân tích tĩnh

| Tệp | SHA-256 | Nhận định |
| :--- | :--- | :--- |
| `McAfee.exe` | `3124FCB79DA0BDF9D0D1995E37B06F7929D83C1C4B60E38C104743BE71170EFE` | Tệp có chữ ký số hợp lệ, bị lợi dụng làm chương trình khởi chạy |
| `McUtil.dll` | `b04d5b8d83246acef2fa3553bdaa16ee212a20090c0524a1e3db6a583732e4af` | DLL loader, không có chữ ký số |
| `McUtil.dll.mc` | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` | Dữ liệu payload được đóng gói/làm rối |

Mẫu sử dụng `McAfee.exe` để kích hoạt DLL độc hại `McUtil.dll` đặt cùng thư mục --- dấu hiệu của **DLL side-loading**.

![image](/assets/images8/1.png)

PEStudio cho thấy `McUtil.dll` là DLL 32-bit, có các API như `VirtualAlloc`, `VirtualProtect`, `GetProcAddress` và `GetModuleHandleA`. Các API này phù hợp với vai trò loader: cấp phát vùng nhớ, phân giải API động và chuẩn bị payload trong bộ nhớ.

![image](/assets/images8/2.png)

## Stage 2 --- Phân tích động

Thực hiện trong VM cô lập bằng cách chạy `McAfee.exe` cùng thư mục với `McUtil.dll` và `McUtil.dll.mc`. Procmon được lọc theo `Process Name is McAfee.exe`.

![image](/assets/images8/3.png)

### 2.1. Kích hoạt và nạp payload

Hoạt động ban đầu tập trung tại `C:\Users\noname\Downloads\malware\`.

![image](/assets/images8/4.png)

Procmon ghi nhận DLL được nạp và tệp `McUtil.dll.mc` được đọc. Các thao tác với vùng nhớ có quyền thực thi là dấu hiệu cần kiểm tra sâu hơn; riêng `PAGE_EXECUTE_READWRITE` chưa đủ để kết luận payload đã được tiêm vào tiến trình khác.

### 2.2. Persistence và che giấu tệp

Mẫu tạo thư mục `C:\ProgramData\McAfee\` và sao chép bộ ba tệp vào đó.

![image](/assets/images8/5.png)

Autoruns cho thấy `McAfee.exe` vẫn được xác minh chữ ký số. Chữ ký hợp lệ của executable không chứng minh các DLL hoặc payload đi kèm là an toàn.

![image](/assets/images8/6.png)

Một cơ chế khởi động cùng phiên đăng nhập được ghi nhận tại:

`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

Ngoài ra, mẫu có dấu hiệu tạo Windows service tại `HKLM\SYSTEM\CurrentControlSet\Services`. Cần xác minh tên service, `ImagePath`, `Start` và `ObjectName` trong registry để xác định chính xác cấu hình và quyền chạy.

![image](/assets/images8/40.png)

Thư mục không hiển thị trong File Explorer nhưng vẫn xuất hiện khi kiểm tra bằng CMD.

![image](/assets/images8/12.png)

![image](/assets/images8/13.png)

Kiểm tra thuộc tính cho thấy thư mục mang thuộc tính `System` và `Hidden`, tương ứng kỹ thuật MITRE ATT&CK **T1564.001 --- Hidden Files and Directories**.

![image](/assets/images8/14.png)

### 2.3. Tiến trình và hoạt động mạng

Procmon ghi nhận hoạt động liên quan đến `C:\Windows\SysWOW64\svchost.exe`.

![image](/assets/images8/7.png)

Một tiến trình `svchost.exe` mới được tạo (PID 6856).

![image](/assets/images8/8.png)

Cần đối chiếu parent PID, command line, trạng thái tiến trình và sự kiện thao tác bộ nhớ để phân biệt **process injection** với **process hollowing**; chỉ riêng việc tạo `svchost.exe` hoặc cấp phát vùng nhớ không đủ chứng minh hollowing.

Tiến trình liên tục gửi TCP SYN tới các địa chỉ trong dải `192.168.129.x` qua cổng `1357`. Đây là dấu hiệu dò tìm host/dịch vụ trong mạng nội bộ; chưa thể kết luận đã lây lan sang máy khác chỉ từ các gói SYN.

Mẫu cũng truy vấn DNS cho `asia.dcsvn.org`, nhận về `76.223.54.146` và `13.248.169.48`.

![image](/assets/images8/9.png)

Tiếp đó, lưu lượng được ghi nhận là HTTP GET qua TCP/443.

![image](/assets/images8/10.png)

HTTP không mã hóa trên cổng 443 là điểm bất thường, nhưng cần kiểm tra trực tiếp giao thức và payload trong PCAP trước khi kết luận. Cổng 443 tự nó không chứng minh lưu lượng là HTTPS hay HTTP.

### 2.4. Tóm tắt hành vi động

| Giai đoạn | Hành vi | Bằng chứng / công cụ |
| :--- | :--- | :--- |
| DLL side-loading | `McAfee.exe` nạp `McUtil.dll` cùng thư mục | Procmon, debugger |
| Unpacking | Đọc `McUtil.dll.mc`, cấp phát và thay đổi quyền vùng nhớ | Procmon, x32dbg |
| Staging | Sao chép các tệp vào `C:\ProgramData\McAfee\`, đặt thuộc tính Hidden/System | Procmon, CMD, Explorer |
| Persistence | Ghi Run key và có dấu hiệu tạo service | Autoruns, Procmon, Registry |
| Process manipulation | Tạo tiến trình `svchost.exe` PID 6856; cần thêm bằng chứng để xác định kỹ thuật injection cụ thể | Procmon, Process Explorer, debugger |
| Network discovery | Gửi TCP SYN tới dải `192.168.129.x:1357` | Process Explorer / TCP-IP, PCAP |
| C2 | DNS tới `asia.dcsvn.org`, sau đó có HTTP GET qua TCP/443 | Wireshark |

## Stage 3 --- Debug loader và unpack payload

Để làm rõ cách DLL kích hoạt payload, sử dụng pseudocode từ IDA rồi theo dõi `McAfee.exe` bằng x32dbg.

### 3.1. Luồng loader

Hàm `sub_10001000` thực hiện các bước chính:

1. Phân giải API từ `kernel32.dll` bằng `GetProcAddress`.
2. Lấy đường dẫn của executable bằng `GetModuleFileNameW`.
3. Ghép tên `McUtil.dll.mc` vào thư mục chứa executable.
4. Mở và đọc dữ liệu payload.
5. Chuyển quyền điều khiển cho đoạn mã loader trong bộ nhớ, sau đó gọi `Sleep(-1)`.

Đoạn pseudocode cho thấy loader chủ động tìm payload tương đối với vị trí của executable, thay vì dùng đường dẫn cố định.

```c
int sub_10001000()
{
    // Pseudocode rút gọn theo luồng phân tích:
    // 1. Resolve API động
    // 2. Lấy thư mục chứa executable
    // 3. Ghép tên McUtil.dll.mc
    // 4. Đọc payload vào bộ nhớ
    // 5. Chuyển điều khiển cho loader/payload
    // 6. Sleep(-1)
}
```

### 3.2. Theo dõi quá trình thực thi

File được debug là `McAfee.exe` bằng x32dbg.

![image](/assets/images8/15.png)

![image](/assets/images8/16.png)

Dùng `Ctrl+G` để tới `LoadLibrary`, sau đó đặt breakpoint tại địa chỉ `75191966` để bắt thời điểm nạp DLL.

![image](/assets/images8/17.png)

![image](/assets/images8/38.png)

Sau khi tiếp tục chạy, debugger dừng tại Entry Point `004046E6`.

![image](/assets/images8/18.png)

Tiếp tục đến `LoadLibraryW`. Tham số đầu tiên trên stack trỏ tới đường dẫn `McUtil.dll`, xác nhận DLL được nạp vào tiến trình.

![image](/assets/images8/19.png)

Dùng `Ctrl+F9` để chạy tới lệnh `ret` của hàm. Sau khi DLL được nạp, luồng thực thi chuyển vào hàm `mcutil.10001000`.

![image](/assets/images8/20.png)

![image](/assets/images8/21.png)

![image](/assets/images8/22.png)

![image](/assets/images8/23.png)

Loader quét ngược chuỗi đường dẫn để tìm dấu `\`, rồi ghép tên `McUtil.dll.mc`. Cách làm này giúp tìm payload trong cùng thư mục với executable.

### 3.3. Giải nén payload trong bộ nhớ

Đặt breakpoint tại `VirtualAlloc` bằng `bp VirtualAlloc`.

![image](/assets/images8/24.png)

![image](/assets/images8/25.png)

Sau khi cấp phát vùng nhớ, luồng thực thi chuẩn bị tham số cho `RtlDecompressBuffer`. Vùng nhớ trả về tại `EAX` là `006D0000`.

![image](/assets/images8/26.png)

![image](/assets/images8/27.png)

Chạy qua hàm giải nén và kiểm tra vùng nhớ tại `006D0000`.

![image](/assets/images8/28.png)

Payload không có header `MZ` chuẩn ở vị trí đầu. Kiểm tra sâu hơn cho thấy dữ liệu có dấu hiệu của PE đã bị biến đổi header; các byte nhận dạng được ghi nhận là `XV`.

![image](/assets/images8/29.png)

Có thể kiểm tra cấu trúc dump bằng Detect It Easy (DIE).

![image](/assets/images8/30.png)

Kết quả VirusTotal được dùng để đối chiếu mẫu đã dump; kết quả phát hiện phụ thuộc thời điểm và engine quét.

![image](/assets/images8/39.png)

### 3.4. Nhóm API đáng chú ý

Bảng dưới đây mô tả **năng lực gợi ý từ import/API**, không mặc nhiên khẳng định mọi chức năng đều đã được thực thi.

![image](/assets/images8/41.png)

| Nhóm | API tiêu biểu | Ý nghĩa phân tích |
| :--- | :--- | :--- |
| Tệp và hệ thống | `CreateFileW`, `ReadFile`, `WriteFile`, `FindFirstFileW`, `SetFileAttributesW` | Đọc/ghi tệp, duyệt thư mục, thay đổi thuộc tính |
| Bộ nhớ và loader | `VirtualAlloc`, `VirtualProtect`, `VirtualAllocEx`, `MapViewOfFile` | Cấp phát, bảo vệ và ánh xạ vùng nhớ; cần xem call stack và tham số để xác định mục đích |
| Tiến trình | `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `CreateRemoteThread`, `CreateProcessW` | Có khả năng thao tác tiến trình khác hoặc tạo tiến trình mới |
| Luồng và đồng bộ | `CreateThread`, `WaitForSingleObject`, `CreateEventW`, `CreateIoCompletionPort` | Tạo worker, đồng bộ và xử lý I/O bất đồng bộ |
| Named pipe | `CreateNamedPipeW`, `ConnectNamedPipe` | Có khả năng giao tiếp IPC qua named pipe |
| Registry | `RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW` | Đọc/ghi cấu hình và có thể thiết lập persistence |
| Windows service | `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`, `ChangeServiceConfigW` | Quản lý và cấu hình service |
| Token / privilege | `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `AdjustTokenPrivileges` | Có khả năng thao tác token hoặc đặc quyền; cần xác minh đường gọi thực tế |
| Bàn phím / cửa sổ | `SetWindowsHookExW`, `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowTextW` | Có thể giám sát input hoặc cửa sổ đang hoạt động |
| Chụp màn hình | `BitBlt`, `CreateDIBSection`, `GetDIBits` | Có khả năng thu ảnh màn hình |
| Môi trường | `GetSystemInfo`, `GlobalMemoryStatus`, `QueryPerformanceCounter` | Thu thập thông tin môi trường; riêng các API này chưa đủ chứng minh anti-VM |
| Mạng | `InternetConnect`, `HttpOpenRequest`, `HttpSendRequestEx`, `WNetOpenEnum`, `WNetEnumResource`, `GetAdaptersInfo`, `gethostbyname` | Giao tiếp web, liệt kê tài nguyên mạng và thu thập cấu hình mạng |
| Cơ sở dữ liệu | `SQLDriverConnect`, `SQLExecDirect` | Có khả năng kết nối/thực thi truy vấn SQL nếu được gọi trong ngữ cảnh phù hợp |

Sau khi giải nén, payload tiếp tục xử lý PE trong bộ nhớ. Quan sát debugger cho thấy vùng nhớ mới tại `021A1000`; theo dõi vùng này qua vòng lặp giúp kiểm tra nội dung payload sau khi ánh xạ.

![image](/assets/images8/31.png)

Sau khi vòng lặp kết thúc, luồng thực thi quay lại loader và thực hiện lời gọi cuối trước khi chuyển sang trạng thái chờ.

![image](/assets/images8/33.png)

Dump bộ nhớ sau giải mã giúp thu thập chuỗi và IoC ở dạng rõ.

![image](/assets/images8/42.png)

Các điểm đáng chú ý gồm domain `asia.dcsvn.org`, nhóm API WinINet, API liệt kê tài nguyên mạng và API lấy thông tin card mạng. Đây là dấu hiệu về năng lực mạng của payload; cần đối chiếu với call stack, PCAP và hành vi thực tế trước khi khẳng định toàn bộ chức năng đã được sử dụng.

### 3.5. Luồng tái tạo

![image](/assets/images8/37.png)

## MITRE ATT&CK mapping

Mapping dưới đây ưu tiên các hành vi có bằng chứng trong bài. Các kỹ thuật chỉ suy ra từ API được ghi chú riêng, tránh coi import API là bằng chứng thực thi.

| Tactic | Technique | Cơ sở mapping | Mức độ bằng chứng |
| :--- | :--- | :--- | :--- |
| Execution | [T1106 --- Native API](https://attack.mitre.org/techniques/T1106/) | Loader phân giải và gọi API Windows trực tiếp | Quan sát qua pseudocode/debugger |
| Persistence | [T1547.001 --- Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | Ghi giá trị tại `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Đã ghi nhận; cần lưu tên/value dữ liệu cụ thể |
| Persistence | [T1543.003 --- Windows Service](https://attack.mitre.org/techniques/T1543/003/) | Có dấu hiệu tạo service tại `HKLM\SYSTEM\CurrentControlSet\Services` | Cần xác minh service name, ImagePath và cấu hình |
| Defense Evasion | [T1574.002 --- DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) | `McAfee.exe` nạp `McUtil.dll` từ thư mục đi kèm | Đã quan sát trong debugger |
| Defense Evasion | [T1564.001 --- Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/) | Thư mục `C:\ProgramData\McAfee\` có thuộc tính Hidden/System | Đã quan sát |
| Defense Evasion | [T1027 --- Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | Payload đóng gói; header PE bị biến đổi theo quan sát | Đã quan sát một phần |
| Defense Evasion | [T1620 --- Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) | Có dấu hiệu xử lý/ánh xạ PE trong bộ nhớ thay vì nạp theo cơ chế chuẩn | Cần xác minh đầy đủ luồng manual mapping |
| Defense Evasion | [T1036.005 --- Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/) | Tên `McAfee.exe` và thư mục `C:\ProgramData\McAfee\` có thể giả dạng phần mềm hợp pháp | Hợp lý, nhưng cần đánh giá ngữ cảnh |
| Defense Evasion | [T1055 --- Process Injection](https://attack.mitre.org/techniques/T1055/) | Có dấu hiệu thao tác bộ nhớ tiến trình và tạo `svchost.exe` | Cần thêm bằng chứng để xác định sub-technique |
| Discovery | [T1046 --- Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Gửi TCP SYN tới nhiều IP trong LAN qua cổng 1357 | Đã quan sát |
| Discovery | [T1135 --- Network Share Discovery](https://attack.mitre.org/techniques/T1135/) | Import `WNetOpenEnum` / `WNetEnumResource` | Năng lực suy ra từ API; cần bằng chứng gọi thực tế |
| Discovery | [T1016 --- System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/) | Import `GetAdaptersInfo` | Năng lực suy ra từ API |
| Discovery | [T1082 --- System Information Discovery](https://attack.mitre.org/techniques/T1082/) | Import API truy vấn thông tin hệ thống/phiên bản | Năng lực suy ra từ API |
| Collection | [T1056.001 --- Keylogging](https://attack.mitre.org/techniques/T1056/001/) | Có nhóm API liên quan hook và trạng thái bàn phím | Chỉ suy ra từ API; cần xác minh hành vi |
| Collection | [T1113 --- Screen Capture](https://attack.mitre.org/techniques/T1113/) | Có nhóm API đồ họa phục vụ chụp màn hình | Chỉ suy ra từ API; cần xác minh hành vi |
| Command and Control | [T1071.001 --- Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | Ghi nhận HTTP GET qua TCP/443 và nhóm API WinINet | Đã quan sát lưu lượng; cần xác nhận nội dung giao thức |
| Command and Control | [T1071.004 --- DNS](https://attack.mitre.org/techniques/T1071/004/) | Truy vấn DNS cho `asia.dcsvn.org` | Đã quan sát DNS; chưa đủ để kết luận DNS được dùng làm kênh C2 |

**Không gán mặc định** `T1055.012 — Process Hollowing`, `T1134.001 — Token Impersonation`, `T1568.002 — Domain Generation Algorithms` hoặc `T1497.003 — Time-Based Evasion`: bằng chứng hiện có trong bài chưa đủ xác nhận chính xác các kỹ thuật đó. `Sleep(-1)` tự nó cũng không chứng minh time-based evasion.

## IOCs

Các IOC dưới đây phản ánh dữ liệu ghi nhận trong lab. Trước khi đưa vào rule chặn hoặc threat intelligence, cần xác minh lại hash, thời điểm thu thập và độ tin cậy của domain/IP.

### 1. File indicators

| Loại | Giá trị | Vai trò / ghi chú |
| :--- | :--- | :--- |
| File SHA-256 | `3124FCB79DA0BDF9D0D1995E37B06F7929D83C1C4B60E38C104743BE71170EFE` | `McAfee.exe` --- executable có chữ ký số, bị lợi dụng để side-load DLL |
| File SHA-256 | `b04d5b8d83246acef2fa3553bdaa16ee212a20090c0524a1e3db6a583732e4af` | `McUtil.dll` --- loader không có chữ ký số |
| File SHA-256 | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` | `McUtil.dll.mc` --- payload đóng gói |
| File SHA-256 | `c22e1765b185d5dd8dc5d6251d49f7133831398c9ef0ea9910cc5998bdb1ad27` | Payload sau khi unpack/dump; cần giữ mẫu và xác minh hash |

### 2. Network indicators

| Loại | Giá trị | Ý nghĩa / giới hạn |
| :--- | :--- | :--- |
| Domain | `asia.dcsvn.org` | Được truy vấn DNS trong lab; cần xác minh trạng thái và quyền sở hữu trước khi block |
| IPv4 | `76.223.54.146` | IP trả về từ truy vấn DNS trong thời điểm phân tích |
| IPv4 | `13.248.169.48` | IP trả về từ truy vấn DNS trong thời điểm phân tích |
| Network behavior | TCP/443, HTTP GET | Lưu lượng được ghi nhận; xác minh bằng PCAP vì port 443 không đồng nghĩa HTTPS |
| Network behavior | TCP SYN tới `192.168.129.x:1357` | Dấu hiệu dò tìm host/dịch vụ trong LAN |

### 3. File system và registry

| Loại | Giá trị | Ý nghĩa |
| :--- | :--- | :--- |
| Directory | `C:\ProgramData\McAfee\` | Thư mục staging; có thuộc tính Hidden/System |
| Dropped file | `C:\ProgramData\McAfee\McAfee.exe` | Bản sao executable |
| Dropped file | `C:\ProgramData\McAfee\McUtil.dll` | DLL loader |
| Dropped file | `C:\ProgramData\McAfee\McUtil.dll.mc` | Payload đóng gói |
| Registry key | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Run key được ghi; cần bổ sung tên value và dữ liệu chính xác |
| Service registry | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` | Vị trí kiểm tra service đáng ngờ; cần bổ sung service name và `ImagePath` |
| Process | `C:\Windows\SysWOW64\svchost.exe` (PID 6856 trong phiên lab) | Tiến trình được tạo trong lúc phân tích; PID chỉ có giá trị trong phiên đó |

## Kết luận

Mẫu sử dụng `McAfee.exe` để side-load `McUtil.dll`, đọc payload từ `McUtil.dll.mc` và giải nén mã trong bộ nhớ. Trong lab, đã ghi nhận việc tạo thư mục staging có thuộc tính Hidden/System, thiết lập Run key, dấu hiệu tạo service, quét TCP trong mạng LAN và truy vấn DNS tới `asia.dcsvn.org`.

Các bước tiếp theo nên ưu tiên: lưu lại cấu hình service và dữ liệu Run key chính xác; xác minh kỹ thuật thao tác `svchost.exe` bằng debugger/memory analysis; lưu PCAP để xác nhận giao thức C2; và phân biệt IOC đã quan sát với năng lực chỉ suy ra từ API.
