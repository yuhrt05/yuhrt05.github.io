---
title: "DFIR LAB 01: Korplug RAT"
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
| Phân loại | Korplug RAT |
| Kỹ thuật nổi bật | DLL side-loading, unpacking/manual mapping, persistence, process injection |
| Thành phần | `McAfee.exe` (ứng dụng ký số bị lợi dụng), `McUtil.dll` (loader), `McUtil.dll.mc` (payload đóng gói) |
| Hành vi quan sát | Persistence, thao tác bộ nhớ, quét mạng LAN, liên lạc C2 |
| Mức độ rủi ro | Cao |
| Nền tảng | Windows |

Bài viết phân tích mẫu qua ba hướng: kiểm tra tĩnh, quan sát hành vi động trong VM và reverse engineering/debug loader để bóc tách luồng giải mã payload.

## Stage 1 --- Phân tích tĩnh

| Tệp | SHA-256 | Nhận định |
| :--- | :--- | :--- |
| `McAfee.exe` | `3124FCB79DA0BDF9D0D1995E37B06F7929D83C1C4B60E38C104743BE71170EFE` | Tệp có chữ ký số hợp lệ, bị lợi dụng làm chương trình khởi chạy |
| `McUtil.dll` | `b04d5b8d83246acef2fa3553bdaa16ee212a20090c0524a1e3db6a583732e4af` | DLL loader, không có chữ ký số |
| `McUtil.dll.mc` | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` | Dữ liệu payload được đóng gói/làm rối |

Mẫu sử dụng `McAfee.exe` để kích hoạt DLL độc hại `McUtil.dll` đặt cùng thư mục --- dấu hiệu của kỹ thuật **DLL side-loading**.

![image](/assets/images8/1.png)

PEStudio cho thấy `McUtil.dll` là DLL 32-bit, import các API như `VirtualAlloc`, `VirtualProtect`, `GetProcAddress` và `GetModuleHandleA`. Các API này phục vụ trực tiếp cho vai trò loader: cấp phát vùng nhớ, phân giải API động và chuẩn bị thực thi payload trong bộ nhớ.

![image](/assets/images8/2.png)

## Stage 2 --- Phân tích động

Thực hiện trong VM cô lập bằng cách chạy `McAfee.exe` cùng thư mục với `McUtil.dll` và `McUtil.dll.mc`. Procmon được lọc theo `Process Name is McAfee.exe`.

![image](/assets/images8/3.png)

### 2.1. Kích hoạt và nạp payload

Hoạt động ban đầu tập trung tại `C:\Users\noname\Downloads\malware\`.

![image](/assets/images8/4.png)

Procmon ghi nhận DLL được nạp và tệp `McUtil.dll.mc` được đọc vào bộ nhớ với quyền thực thi (`PAGE_EXECUTE_READWRITE`) để chuẩn bị cho giai đoạn giải mã và inject.

### 2.2. Persistence và che giấu tệp

Mẫu tạo thư mục `C:\ProgramData\McAfee\` và sao chép bộ ba tệp vào đó để duy trì sự hiện diện trên hệ thống.

![image](/assets/images8/5.png)

Autoruns cho thấy `McAfee.exe` hiển thị chữ ký số hợp lệ từ McAfee, giúp mã độc dễ dàng qua mặt các giải pháp phòng thủ endpoint dựa trên danh tiếng file.

![image](/assets/images8/6.png)

Mã độc thiết lập cơ chế khởi động cùng phiên người dùng tại:

`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

Đồng thời, mẫu tạo thêm Windows service tại `HKLM\SYSTEM\CurrentControlSet\Services` để đảm bảo quyền persistence cấp hệ thống.

![image](/assets/images8/40.png)

Thư mục `C:\ProgramData\McAfee\` không hiển thị trong File Explorer nhưng xuất hiện khi kiểm tra qua command prompt.

![image](/assets/images8/12.png)

![image](/assets/images8/13.png)

Kiểm tra thuộc tính cho thấy thư mục mang cờ `System` và `Hidden`, tương ứng kỹ thuật MITRE ATT&CK **T1564.001 --- Hidden Files and Directories**.

![image](/assets/images8/14.png)

### 2.3. Tiến trình và hoạt động mạng

Procmon ghi nhận hoạt động tương tác với `C:\Windows\SysWOW64\svchost.exe`.

![image](/assets/images8/7.png)

Một tiến trình `svchost.exe` mới được tạo (PID 6856).

![image](/assets/images8/8.png)

Mã độc sử dụng kỹ thuật process injection vào `svchost.exe` để che giấu mã độc dưới tiến trình hệ thống hợp lệ và thực hiện các hành vi độc hại tiếp theo.

Tiến trình liên tục gửi gói TCP SYN tới các địa chỉ trong dải `192.168.129.x` qua cổng `1357` nhằm dò quét host và dịch vụ trong mạng LAN (Network Service Discovery).

Mẫu thực hiện truy vấn DNS cho domain C2 `asia.dcsvn.org`, phân giải về các IP `76.223.54.146` và `13.248.169.48`.

![image](/assets/images8/9.png)

Tiếp đó, lưu lượng C2 được gửi qua cổng 443 dưới dạng HTTP GET.

![image](/assets/images8/10.png)

### 2.4. Tóm tắt hành vi động

| Giai đoạn | Hành vi | Bằng chứng / công cụ |
| :--- | :--- | :--- |
| DLL side-loading | `McAfee.exe` nạp `McUtil.dll` cùng thư mục | Procmon, debugger |
| Unpacking | Đọc `McUtil.dll.mc`, cấp phát và thay đổi quyền vùng nhớ | Procmon, x32dbg |
| Staging | Sao chép các tệp vào `C:\ProgramData\McAfee\`, đặt thuộc tính Hidden/System | Procmon, CMD, Explorer |
| Persistence | Ghi Run key và tạo Windows service | Autoruns, Procmon, Registry |
| Process manipulation | Tạo tiến trình `svchost.exe` PID 6856 và thực hiện process injection | Procmon, Process Explorer, debugger |
| Network discovery | Gửi TCP SYN tới dải `192.168.129.x:1357` | Process Explorer / TCP-IP, PCAP |
| C2 | DNS tới `asia.dcsvn.org`, HTTP GET qua TCP/443 | Wireshark |

## Stage 3 --- Debug loader và unpack payload

Sử dụng pseudocode từ IDA kết hợp x32dbg để lần theo luồng nạp và giải mã payload của loader.

### 3.1. Luồng loader

Hàm `sub_10001000` thực hiện các bước chính:

1. Phân giải API từ `kernel32.dll` bằng `GetProcAddress`.
2. Lấy đường dẫn của executable bằng `GetModuleFileNameW`.
3. Ghép tên `McUtil.dll.mc` vào thư mục chứa executable.
4. Mở và đọc dữ liệu payload.
5. Chuyển quyền điều khiển cho đoạn mã loader trong bộ nhớ, sau đó gọi `Sleep(-1)`.

Đoạn pseudocode cho thấy loader chủ động định vị payload tương đối với vị trí thực thi của executable.

```c
int sub_10001000()
{
    // 1. Resolve API động
    // 2. Lấy thư mục chứa executable
    // 3. Ghép tên McUtil.dll.mc
    // 4. Đọc payload vào bộ nhớ
    // 5. Chuyển điều khiển cho loader/payload
    // 6. Sleep(-1)
}
```

### 3.2. Theo dõi quá trình thực thi

Mở `McAfee.exe` trong x32dbg.

![image](/assets/images8/15.png)

![image](/assets/images8/16.png)

Dùng `Ctrl+G` để tới `LoadLibrary`, đặt breakpoint tại địa chỉ `75191966` để bắt thời điểm nạp DLL.

![image](/assets/images8/17.png)

![image](/assets/images8/38.png)

Sau khi tiếp tục chạy, debugger dừng tại Entry Point `004046E6`.

![image](/assets/images8/18.png)

Tiến trình chạy tới `LoadLibraryW`. Tham số đầu tiên trên stack trỏ tới đường dẫn `McUtil.dll`, nạp DLL độc hại vào không gian bộ nhớ.

![image](/assets/images8/19.png)

Dùng `Ctrl+F9` để chạy tới lệnh `ret` của hàm. Sau khi DLL được nạp, luồng thực thi chuyển vào hàm `mcutil.10001000`.

![image](/assets/images8/20.png)

![image](/assets/images8/21.png)

![image](/assets/images8/22.png)

![image](/assets/images8/23.png)

Loader quét ngược chuỗi đường dẫn tìm dấu `\` để ghép tên `McUtil.dll.mc`, đảm bảo tải đúng payload nằm cùng thư mục.

### 3.3. Giải nén payload trong bộ nhớ

Đặt breakpoint tại `VirtualAlloc` bằng lệnh `bp VirtualAlloc`.

![image](/assets/images8/24.png)

![image](/assets/images8/25.png)

Sau khi cấp phát vùng nhớ, luồng thực thi chuẩn bị tham số cho `RtlDecompressBuffer`. Vùng nhớ trả về tại `EAX` là `006D0000`.

![image](/assets/images8/26.png)

![image](/assets/images8/27.png)

Thực thi qua hàm giải nén và kiểm tra vùng nhớ tại `006D0000`.

![image](/assets/images8/28.png)

Payload không sử dụng header `MZ` chuẩn mà đã bị biến đổi header với 2 byte nhận dạng là `XV`.

![image](/assets/images8/29.png)

Kiểm tra cấu trúc file dump bằng Detect It Easy (DIE).

![image](/assets/images8/30.png)

Đối chiếu kết quả quét hash payload đã dump trên VirusTotal.

![image](/assets/images8/39.png)

### 3.4. Nhóm API đáng chú ý

Bảng dưới đây tổng hợp các nhóm API chính được payload sử dụng:

![image](/assets/images8/41.png)

| Nhóm | API tiêu biểu | Ý nghĩa phân tích |
| :--- | :--- | :--- |
| Tệp và hệ thống | `CreateFileW`, `ReadFile`, `WriteFile`, `FindFirstFileW`, `SetFileAttributesW` | Đọc/ghi tệp, duyệt thư mục, thao tác thuộc tính tệp |
| Bộ nhớ và loader | `VirtualAlloc`, `VirtualProtect`, `VirtualAllocEx`, `MapViewOfFile` | Cấp phát, thay đổi thuộc tính bảo vệ và ánh xạ payload vào bộ nhớ |
| Tiến trình | `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `CreateRemoteThread`, `CreateProcessW` | Tạo tiến trình mới và can thiệp bộ nhớ tiến trình (Process Injection) |
| Luồng và đồng bộ | `CreateThread`, `WaitForSingleObject`, `CreateEventW`, `CreateIoCompletionPort` | Quản lý worker thread, đồng bộ và xử lý I/O bất đồng bộ |
| Named pipe | `CreateNamedPipeW`, `ConnectNamedPipe` | Giao tiếp liên tiến trình (IPC) qua Named Pipe |
| Registry | `RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW` | Ghi cấu hình và thiết lập cơ chế persistence |
| Windows service | `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`, `ChangeServiceConfigW` | Quản lý, khởi tạo và cấu hình Windows service |
| Token / privilege | `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `AdjustTokenPrivileges` | Thao tác token và leo thang đặc quyền hệ thống |
| Bàn phím / cửa sổ | `SetWindowsHookExW`, `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowTextW` | Keylogger, theo dõi phím bấm và cửa sổ đang hoạt động |
| Chụp màn hình | `BitBlt`, `CreateDIBSection`, `GetDIBits` | Thu thập hình ảnh màn hình nạn nhân (Screen Capture) |
| Môi trường | `GetSystemInfo`, `GlobalMemoryStatus`, `QueryPerformanceCounter` | Thu thập thông tin cấu hình phần cứng và hệ điều hành |
| Mạng | `InternetConnect`, `HttpOpenRequest`, `HttpSendRequestEx`, `WNetOpenEnum`, `WNetEnumResource`, `GetAdaptersInfo`, `gethostbyname` | Giao tiếp C2 qua HTTP/web, liệt kê tài nguyên mạng và card mạng |
| Cơ sở dữ liệu | `SQLDriverConnect`, `SQLExecDirect` | Kết nối và thực thi truy vấn cơ sở dữ liệu SQL |

Sau khi giải nén, payload tiếp tục xử lý PE trong bộ nhớ. Quan sát debugger xuất hiện vùng nhớ mới tại `021A1000`; theo dõi vùng này qua vòng lặp ghi nhận nội dung payload sau khi ánh xạ hoàn chỉnh.

![image](/assets/images8/31.png)

Kết thúc vòng lặp giải mã, luồng thực thi quay lại loader và gọi lệnh chuyển sang trạng thái chờ.

![image](/assets/images8/33.png)

Dump bộ nhớ sau giải mã thu được các chuỗi IoC ở dạng văn bản rõ.

![image](/assets/images8/42.png)

Các chuỗi quan trọng gồm domain C2 `asia.dcsvn.org`, nhóm hàm WinINet và các API thu thập thông tin mạng, xác nhận đầy đủ năng lực do thám và giao tiếp C2 của payload.

### 3.5. Luồng tái tạo

![image](/assets/images8/37.png)

## MITRE ATT&CK mapping

Bảng mapping các kỹ thuật theo khung MITRE ATT&CK:

| Tactic | Technique | Cơ sở mapping | Mức độ xác nhận |
| :--- | :--- | :--- | :--- |
| Execution | [T1106 --- Native API](https://attack.mitre.org/techniques/T1106/) | Loader phân giải và gọi trực tiếp các API Windows | Xác nhận qua Debugger |
| Persistence | [T1547.001 --- Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | Ghi key khởi động tại `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Xác nhận qua Registry |
| Persistence | [T1543.003 --- Windows Service](https://attack.mitre.org/techniques/T1543/003/) | Tạo service độc hại tại `HKLM\SYSTEM\CurrentControlSet\Services` | Xác nhận qua Service Control Manager |
| Defense Evasion | [T1574.002 --- DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) | `McAfee.exe` nạp `McUtil.dll` từ cùng thư mục | Xác nhận qua Debugger |
| Defense Evasion | [T1564.001 --- Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/) | Thư mục `C:\ProgramData\McAfee\` gắn thuộc tính Hidden/System | Xác nhận qua CMD / File Attributes |
| Defense Evasion | [T1027 --- Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | Payload đóng gói và làm mờ header PE (`XV`) | Xác nhận qua Memory Dump / DIE |
| Defense Evasion | [T1620 --- Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) | Giải mã và ánh xạ thủ công PE payload trực tiếp trong bộ nhớ | Xác nhận qua Debugger |
| Defense Evasion | [T1036.005 --- Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/) | Giả dạng ứng dụng hợp pháp McAfee và đặt tại `C:\ProgramData\McAfee\` | Xác nhận qua File Path |
| Defense Evasion | [T1055 --- Process Injection](https://attack.mitre.org/techniques/T1055/) | Can thiệp bộ nhớ và inject mã độc vào `svchost.exe` | Xác nhận qua Procmon / Debugger |
| Discovery | [T1046 --- Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Gửi gói TCP SYN quét dải IP LAN qua cổng 1357 | Xác nhận qua Network Capture |
| Discovery | [T1135 --- Network Share Discovery](https://attack.mitre.org/techniques/T1135/) | Import các API `WNetOpenEnum` / `WNetEnumResource` | Xác nhận qua Import Table |
| Discovery | [T1016 --- System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/) | Import `GetAdaptersInfo` để lấy thông tin card mạng | Xác nhận qua Import Table |
| Discovery | [T1082 --- System Information Discovery](https://attack.mitre.org/techniques/T1082/) | Import các API truy vấn cấu hình và phiên bản hệ điều hành | Xác nhận qua Import Table |
| Collection | [T1056.001 --- Keylogging](https://attack.mitre.org/techniques/T1056/001/) | Import các hàm hook bàn phím và lấy trạng thái phím bấm | Xác nhận qua API capability |
| Collection | [T1113 --- Screen Capture](https://attack.mitre.org/techniques/T1113/) | Import API đồ họa `BitBlt`, `GetDIBits` phục vụ chụp màn hình | Xác nhận qua API capability |
| Command and Control | [T1071.001 --- Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | Gửi request HTTP GET qua cổng 443 bằng WinINet | Xác nhận qua Wireshark |
| Command and Control | [T1071.004 --- DNS](https://attack.mitre.org/techniques/T1071/004/) | Phân giải tên miền C2 `asia.dcsvn.org` qua DNS | Xác nhận qua DNS query |

## IOCs

Tổng hợp các chỉ số thỏa hiệp (Indicators of Compromise) thu thập được từ mẫu:

### 1. File indicators

| Loại | Giá trị | Vai trò / ghi chú |
| :--- | :--- | :--- |
| File SHA-256 | `3124FCB79DA0BDF9D0D1995E37B06F7929D83C1C4B60E38C104743BE71170EFE` | `McAfee.exe` --- Executable có chữ ký số bị lợi dụng để side-load DLL |
| File SHA-256 | `b04d5b8d83246acef2fa3553bdaa16ee212a20090c0524a1e3db6a583732e4af` | `McUtil.dll` --- DLL loader |
| File SHA-256 | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` | `McUtil.dll.mc` --- Payload bị mã hóa / đóng gói |
| File SHA-256 | `c22e1765b185d5dd8dc5d6251d49f7133831398c9ef0ea9910cc5998bdb1ad27` | Payload sau khi được giải mã / dump từ bộ nhớ |

### 2. Network indicators

| Loại | Giá trị | Ý nghĩa |
| :--- | :--- | :--- |
| Domain | `asia.dcsvn.org` | Domain C2 của Korplug RAT |
| IPv4 | `76.223.54.146` | Địa chỉ IP C2 trả về từ truy vấn DNS |
| IPv4 | `13.248.169.48` | Địa chỉ IP C2 trả về từ truy vấn DNS |
| Network behavior | TCP/443, HTTP GET | Giao thức truyền tin C2 qua cổng 443 |
| Network behavior | TCP SYN tới `192.168.129.x:1357` | Dò quét cổng nội bộ trong mạng LAN |

### 3. File system và registry

| Loại | Giá trị | Ý nghĩa |
| :--- | :--- | :--- |
| Directory | `C:\ProgramData\McAfee\` | Thư mục staging mang thuộc tính Hidden/System |
| Dropped file | `C:\ProgramData\McAfee\McAfee.exe` | Bản sao executable sạch để kích hoạt |
| Dropped file | `C:\ProgramData\McAfee\McUtil.dll` | DLL loader độc hại |
| Dropped file | `C:\ProgramData\McAfee\McUtil.dll.mc` | Payload đóng gói |
| Registry key | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Registry Run key duy trì quyền khởi động cùng user |
| Service registry | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` | Service độc hại duy trì quyền persistence hệ thống |
| Process | `C:\Windows\SysWOW64\svchost.exe` (PID 6856) | Tiến trình hệ thống bị chèn mã độc (Process Injection) |

## Kết luận

Mẫu Korplug RAT sử dụng kỹ thuật DLL side-loading kinh điển thông qua tệp `McAfee.exe` hợp lệ để kích hoạt loader `McUtil.dll` và bóc tách payload `McUtil.dll.mc` trong bộ nhớ. Sau khi chiếm quyền điều khiển, mã độc thiết lập cơ chế persistence qua Registry Run key và Windows service, ẩn thư mục staging dưới thuộc tính System/Hidden, thực hiện dò quét mạng LAN và kết nối C2 tới domain `asia.dcsvn.org`.
