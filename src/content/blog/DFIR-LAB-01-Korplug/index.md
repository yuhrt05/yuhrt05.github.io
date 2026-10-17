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
|---|---|
| **Tên malware** | McAfee.exe |
| **Loại malware** | Remote Access Trojan (RAT) / Korplug |
| **Kỹ thuật chính** | DLL Side-loading |
| **Tệp tin liên quan** | `McAfee.exe` (File sạch), `McUtil.dll` (DLL Loader), `McUtil.dll.mc` (Payload shellcode) |
| **Hành vi chính** | Persistence; Process Injection; LAN scanning; C2 Server|
| **Mức độ nguy hiểm** | Cao (Có khả năng đánh cắp thông tin và lây lan trong mạng nội bộ) |
| **Hệ điều hành** | Windows |

## Tiến hành phân tích
### Stage 1

| Tên tệp | SHA256 Hash | Đặc điểm nhận dạng |
|---|---|---|
| McAfee.exe | `3124FCB79DA0BDF9D0D1995E37B06F7929D83C1C4B60E38C104743BE71170EFE` | Tệp thực thi hợp lệ, đóng vai trò "vùng đệm" |
| McUtil.dll | `b04d5b8d83246acef2fa3553bdaa16ee212a20090c0524a1e3db6a583732e4af` | Thư viện Loader, không có chữ ký số |
| McUtil.dll.mc | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` | Tệp shellcode chính đã bị làm rối (Obfuscated) |

- Mã độc lợi dụng sự tin tưởng của hệ thống vào `McAfee.exe` có chữ ký số hợp lệ để nạp `file DLL` độc hại cùng tên trong cùng thư mục là `McUtil.dll`.

![image](/assets/images8/1.png)

- Dùng `PEstudio` để trích xuất ra các hàm/API đã được import trong `McUtil.dll`: Đây là một `DLL 32-bit` hoạt động như một `loader/unpacker`: dùng `VirtualAlloc/VirtualProtect` và `GetProcAddress/GetModuleHandleA` với `import` từ `KERNEL32` để `giải nén/cấp phát vùng nhớ` và `tiêm mã độc` vào bộ nhớ

![image](/assets/images8/2.png)

### Stage 2

- Thực hiện trong môi trường `VM`. Chạy trực tiếp file `McAfee.exe` trong thư mục cùng chứa 2 file là `McUtil.dll` và `McUtil.dll.mc` với quyền `Administrator`

Dùng `Process Monitor` để bắt được luồng thực thi theo thời gian thực và `filter` chỉ riêng với `Process Name` là `McAfee.exe`

![image](/assets/images8/3.png)

- Xem qua một lượt ta có thể thấy rõ được 2 `giai đoạn chính` của quá trình thực thi

#### Giai đoạn kích hoạt

- Địa điểm hoạt động: Chủ yếu là trong `C:\Users\noname\Downloads\malware\`

![image](/assets/images8/4.png)

- Hành vi quan trọng: Mã độc tạo một mapping cho `McUtil.dll` với quyền `PAGE_EXECUTE_READWRITE`

- Load Image: Xác nhận `McUtil.dll` đã được nạp vào không gian bộ nhớ của `McAfee.exe`

- ReadFile: Nó bắt đầu đọc file và thực thi payload `McUtil.dll.mc` (Offset 0, length hơn `116k bytes`)

#### Giai đoạn persistence

- Xuất hiện đường dẫn mới: `C:\ProgramData\McAfee\`

![image](/assets/images8/5.png)

- Hành vi quan trọng: Nó đang tạo ra các thư mục mới tên là `McAfee` và thực hiện sao chép y nguyên chính nó gồm 3 file gốc vào trong `C:\ProgramData`. Đây là thư mục ẩn, thường được malware dùng để lẩn trốn để thiết lập cơ chế `persistence`.

Trong `Autoruns`, ta có thể dễ dàng thấy file `McAfee.exe` vẫn được `Verified` vì nó không bị chỉnh sửa mã nguồn nên vẫn hoàn toàn hợp pháp.

![image](/assets/images8/6.png)

- Vị trí Registry: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

Ngoài ra chúng còn Persistence bằng cách tạo 1 service mới để nghiễm nhiên chúng được hoạt động dưới quyền `SYSTEM` trong hệ thống

![image](/assets/images8/40.png)

- Vị trí: `HKLM\System\CurrentControlSet\Services`

Check thử theo đường dẫn tại `C:\ProgramData\McAfee` bằng `Explorer` thì không thấy có `folder` nào tên `McAfee`

![image](/assets/images8/12.png)

Mình thử check trên `cmd` thì thấy vẫn xuất hiện

![image](/assets/images8/13.png)

Tìm hiểu một chút thì mình có được kĩ thuật mà `malware` sử dụng tại [Hide Artifacts: Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)

- Thuộc tính SH: Mã độc đã thiết lập hai thuộc tính quan trọng cho thư mục này là `System (S)` và `Hidden (H)`.

![image](/assets/images8/14.png)

Vẫn tiếp tục trong `Process Monitor`, thấy được `malware` đang thực hiện `Process Injection` trực tiếp vào một phần mềm hợp pháp của hệ thống là `C:\Windows\SysWOW64\svchost.exe`

![image](/assets/images8/7.png)

- Dấu hiệu đặc trưng: Hành động `CreateFileMapping` với quyền `PAGE_EXECUTE_READWRITE` lên svchost.exe.

- Lệnh `Process Create` đã tạo ra một tiến trình `svchost.exe` mới `(PID 6856)`.

- Mục đích: Mã độc sử dụng tiến trình `svchost.exe` (một tiến trình nền phổ biến của Windows) làm `vỏ bọc` để thực thi các hành vi độc hại ẩn dưới danh nghĩa hệ thống, nhằm qua mặt người dùng và các phần mềm giám sát đơn giản.

Chuyển sang `Process Explorer` ta có thể thấy được hành vi của tiến trình `svchost` được sinh ra bởi `malware`

![image](/assets/images8/8.png)

- Hành vi Quét mạng (LAN Scanning / Discovery):
    - Tiến trình bị tiêm mã `svchost.exe` đang liên tục gửi các gói tin `TCP SYN` tới các địa chỉ `IP` trong mạng nội bộ (cụ thể là `192.168.129.x`) qua cổng `1357`.
    - Trạng thái `SYN_SENT` cho thấy mã độc đang cố gắng dò tìm các thiết bị đang hoạt động hoặc các dịch vụ đang mở trong mạng LAN nhưng chưa nhận được phản hồi
    - Mục đích: Đây là giai đoạn `Reconnaissance`. Mã độc sau khi xâm nhập vào một máy sẽ tìm cách lây lan sang các máy khác trong cùng mạng hoặc tìm kiếm các máy chủ có lỗ hổng để thực hiện bước tiếp theo.

Kết hợp với những hành vi của `malware` thực hiện ở nội bộ thì nó cũng có những kết nối đến `C2 server` để nhận tín hiệu

![image](/assets/images8/9.png)

- Máy nạn nhân `192.168.129.128` thực hiện truy vấn `DNS` cho tên miền: `asia.dcsvn.org`
- Kết quả phân giải: Tên miền này trỏ về các địa chỉ IP công cộng: `76.223.54.146` và `13.248.169.48` đây chính là địa chỉ của `C2 server`

Tiếp theo, thực hiện `HTTP GET request` tới cổng `443` và địa chỉ IP là địa chỉ của `C2 Server`

![image](/assets/images8/10.png)

- Điểm bất thường: Thông thường cổng `443` dành cho `HTTPS` (mã hóa SSL/TLS). Ở đây, mã độc sử dụng `HTTP` thuần (không mã hóa) trên cổng `443`.
- Mục đích: Đây là kỹ thuật ẩn mình (`Evasion`) nhằm đánh lừa các hệ thống tường lửa hoặc giám sát mạng chỉ kiểm tra số cổng mà không kiểm tra nội dung gói tin (`Deep Packet Inspection`), khiến lưu lượng này trông giống như duyệt web bảo mật thông thường.

#### Tổng hợp quá trình phân tích động

| STT | Phase | Hành vi chi tiết (Behavior) | Công cụ xác nhận | Dấu hiệu (Artifacts/IoCs) |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **DLL Side-loading** | `McAfee.exe` (tệp tin hợp lệ bị lợi dụng) nạp `McUtil.dll` (tệp tin độc hại) từ cùng thư mục thực thi. | ProcMon / ProcExp | `McUtil.dll` nằm ngoài thư mục hệ thống chuẩn. |
| **2** | **Unpacking / Decoding** | Giải mã shellcode từ tệp `.mc`. Cấp phát và thay đổi quyền vùng nhớ thành **RWX** (`PAGE_EXECUTE_READWRITE`). | PEStudio / ProcMon | Hàm `VirtualProtect`, `VirtualAlloc`, `CreateFileMapping`. |
| **3** | **Staging & Stealth** | Thư mục ẩn trong File Explorer; lệnh attrib hiện mã SH. | ProcMon/CMD/Explorer | Tệp tin xuất hiện tại `C:\ProgramData\McAfee\`. |
| **4** | **Persistence** | Ghi giá trị vào Registry để mã độc tự khởi động lại cùng hệ thống Windows. | Autoruns / ProcMon | Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. |
| **5** | **Process Injection** | Sử dụng kỹ thuật **Process Hollowing** để tiêm mã độc từ `McAfee.exe` vào tiến trình hệ thống `svchost.exe`. | ProcExp / ProcMon | `svchost.exe` có tiến trình cha (Parent) đã kết thúc hoặc không hợp lệ. |
| **6** | **Internal Reconnaissance** | Tiến trình `svchost.exe` thực hiện quét dải mạng LAN để tìm kiếm các máy trạm khác. | ProcExp (TCP/IP) | Quét TCP Port **1357** tới các IP nội bộ `192.168.129.x`. |
| **7** | **Command & Control (C2)** | Truy vấn DNS và gửi tín hiệu Beaconing về máy chủ điều khiển của kẻ tấn công. | Wireshark | Domain: `asia.dcsvn.org`; Giao thức **HTTP GET** qua Port **443**. |

---

### Stage 3

- Vì `McAfee.exe` là một tệp tin hợp pháp và có chữ ký số, kẻ tấn công đã lợi dụng nó làm để nạp mã độc. Để hiểu rõ việc cách thức này kích hoạt mã độc bên trong, ta sẽ kết hợp `phân tích tĩnh` (sử dụng mã giả từ IDA) để soi luồng thực thi của `McUtil.dll`, từ đó làm tiền đề cho việc `Phân tích động` bằng các trình `Debugger` về sau.

```c
int sub_10001000()
{
  HMODULE ModuleHandleA; // eax
  LPVOID (__stdcall *VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD); // eax
  WCHAR *v2; // esi
  HMODULE v3; // eax
  LPWSTR (__stdcall *lstrcpyW)(LPWSTR, LPCWSTR); // eax
  DWORD v5; // ecx
  HMODULE v6; // eax
  HANDLE (__stdcall *CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); // eax
  HMODULE v8; // eax
  BOOL (__stdcall *ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED); // eax
  __int64 v10; // rax
  int v11; // ecx
  HMODULE v12; // eax
  void (__stdcall *Sleep)(DWORD); // eax
  int v15; // [esp+0h] [ebp-18h]
  int v16; // [esp+4h] [ebp-14h]
  _DWORD v17[2]; // [esp+8h] [ebp-10h] BYREF
  HANDLE v18; // [esp+10h] [ebp-8h]
  DWORD ModuleFileNameW; // [esp+14h] [ebp-4h] BYREF
  int savedregs; // [esp+18h] [ebp+0h] BYREF

  ModuleHandleA = GetModuleHandleA("kernel32.dll");
  VirtualAlloc = (LPVOID (__stdcall *)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(ModuleHandleA, "VirtualAlloc");
  v2 = (WCHAR *)VirtualAlloc(0, 1048699, 4096, 64);
  ModuleFileNameW = GetModuleFileNameW(0, v2, 0x101Bu);
  v3 = GetModuleHandleA("kernel32.dll");
  lstrcpyW = (LPWSTR (__stdcall *)(LPWSTR, LPCWSTR))GetProcAddress(v3, "lstrcpyW");
  v5 = --ModuleFileNameW;
  if ( ModuleFileNameW )
  {
    while ( v2[v5] != 92 )
    {
      ModuleFileNameW = --v5;
      if ( !v5 )
        goto LABEL_6;
    }
    lstrcpyW(&v2[v5 + 1], L"McUtil.dll.mc");
  }
LABEL_6:
  v6 = GetModuleHandleA("kernel32.dll");
  CreateFileW = (HANDLE (__stdcall *)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(v6, "CreateFileW");
  v18 = CreateFileW(v2, 0x80000000, 1, 0, 3, 0, 0);
  if ( v18 != (HANDLE)-1 )
  {
    v17[1] = v2;
    v8 = GetModuleHandleA("kernel32.dll");
    ReadFile = (BOOL (__stdcall *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(v8, "ReadFile");
    v10 = ((__int64 (__stdcall *)(HANDLE, WCHAR *, int, DWORD *, _DWORD, int, int))ReadFile)(
            v18,
            v2,
            1048699,
            &ModuleFileNameW,
            0,
            v15,
            v16);
    ((void (__cdecl *)(_DWORD, _DWORD, _DWORD, int, FARPROC (__stdcall *)(HMODULE, LPCSTR), _DWORD *, int *, HMODULE (__stdcall *)(LPCSTR), WCHAR *))v2)(
      0,
      v10,
      HIDWORD(v10),
      v11,
      GetProcAddress,
      v17,
      &savedregs,
      GetModuleHandleA,
      v2);
    v12 = GetModuleHandleA("kernel32.dll");
    Sleep = (void (__stdcall *)(DWORD))GetProcAddress(v12, "Sleep");
    ((void (__cdecl *)(int))Sleep)(-1);
  }
  return 0;
}
```
### Luồng thực thi mã độc

![image](/assets/images8/15.png)

File cần debug là `McAfee.exe`, mình dùng `x32Dbg` để thực hiện

![image](/assets/images8/16.png)

- Nhấn `Ctrl + G` để nhảy đến hàm `LoadLibrary` 

![image](/assets/images8/17.png)

- Tiến hành đặt `breakpoint` tại địa chỉ `75191966`, dùng để chặn bắt thời điểm `McUtil.dll` được nạp vào bộ nhớ nhằm kiểm soát và phân tích hành vi thực thi của mã độc.

![image](/assets/images8/38.png)

Nhấn `F9`, thấy dừng tại `Entry Point (004046E6)`: Điểm bắt đầu thực thi logic chính của `McAfee.exe` để chuẩn bị nạp `DLL độc hại`.

![image](/assets/images8/18.png)

Tiếp tục nhấn `F9`, thấy được dừng tại hàm `LoadLibraryW`: Xác nhận tiến trình `McAfee.exe` đang thực hiện nạp tệp độc hại `McUtil.dll` vào bộ nhớ

![image](/assets/images8/19.png)
  
  - Dấu hiệu: Tham số đầu tiên trên Stack `([esp+4])` trỏ thẳng đến đường dẫn của tệp `McUtil.dll`

Nhấn `Ctrl F9` để chạy nốt hàm nạp thư viện và dừng lại ở lệnh `ret` (trở về)

![image](/assets/images8/20.png)

Sau khi nạp xong DLL, tiến trình thực hiện `jmp` trực tiếp từ file thực thi hợp lệ `McAfee.exe` vào hàm độc hại `mcutil.10001000` 

![image](/assets/images8/21.png)

Ta đã vào được luồng thực thi của `McUtil.dll` giống như những gì đã thấy được khi phân tích mã giả trong `IDA`

![image](/assets/images8/22.png)


![image](/assets/images8/23.png)

- Hành vi kỹ thuật: Mã độc thực hiện vòng lặp quét ngược (Backwards scan) chuỗi đường dẫn của McAfee.exe để tìm ký tự gạch chéo \
- Mục đích: Tách phần tên tệp thực thi `McAfee.exe` ra khỏi đường dẫn đầy đủ để xác định thư mục làm việc.
- Kết quả: Ngay sau vòng lặp này tại `10001072`, mã độc sẽ ghép tên tệp `McUtil.dll.mc` vào vị trí đó. Điều này giúp mã độc luôn tìm thấy tệp payload đi kèm bất kể nó được đặt ở thư mục nào trên máy nạn nhân.

Vì ta đã biết được mã độc sẽ sử dụng `VirtualAlloc` để tạo một vùng nhớ trống, nên ta sẽ đặt một `breakpoint` vào đúng hàm này bằng lệnh `bp VirtualAlloc`

![image](/assets/images8/24.png)

Nhấn `F9` để chạy thằng đến hàm đó 

![image](/assets/images8/25.png)

`Ctrl F9` để chạy hết hàm cấp phát vùng nhớ, sau đó luồng thực thi sẽ di chuyển vào giai đoạn chuẩn bị các tham số cho hàm `RtlDecompressBuffer` để giải nén `payload` thật sự từ tệp `.mc` vào vùng nhớ vừa được cấp phát

![image](/assets/images8/26.png)

Quan sát giá trị thanh ghi `EAX` vừa được cấp phát là `006D0000`, ta sẽ follow theo vùng nhớ này

![image](/assets/images8/27.png)

Tiếp tục `F8` đến hết hàm `RtlDecompressBuffer` tức là `shellcode` sẽ được giải mã và ghi vào vùng nhớ `006D0000`

![image](/assets/images8/28.png)

Thấy có dấu hiệu ban đầu là header không phải là `MZ`, nên mình đã thử kéo xuống xem phần thân bên dưới thì đã thấy có sự xuất hiện của các `API hệ thống` được gọi

![image](/assets/images8/29.png)

Nội dung sau khi giải của vùng nhớ thực chất là một tệp `PE` hoàn chỉnh, nhưng các giá trị đặc trưng ở phần `Header` đã bị làm biến dạng để tránh bị phát hiện của `AV`. Cụ thể, các dấu hiệu nhận biết tiêu chuẩn như `MZ` và `PE` đã được thay thế bằng ký tự `XV`. Ta có thể check nó bằng `die`

![image](/assets/images8/30.png)

Xác nhận tiếp bằng Virustotal, xác nhận rằng ta đã dump được thành công payload

![image](/assets/images8/39.png)

Sau quá trình reverse, ta có được kết luận về các nhóm API đáng chú ý được malware sử dụng:

![image](/assets/images8/41.png)

| Nhóm chức năng | API tiêu biểu | Diễn giải kỹ thuật |
|---|---|---|
| File/System Operations | `CreateFileW`, `ReadFile`, `WriteFile`, `GetFileSize`, `SetFilePointer`, `SetEndOfFile`, `FlushFileBuffers`, `SetFileTime`, `GetFileTime`, `CreateDirectoryW`, `RemoveDirectoryW`, `DeleteFileW`, `FindFirstFileW`, `FindNextFileW`, `GetFileAttributesW`, `SetFileAttributesW` | Cho phép payload đọc/ghi dữ liệu, staging thêm tệp, dọn dấu vết, duyệt cây thư mục, thao tác timestamp và ẩn file/thư mục. Nhóm API này khớp tốt với hành vi tạo thư mục `C:\ProgramData\McAfee\` và gắn thuộc tính `Hidden/System` đã quan sát ở phần động. |
| Process Injection & Process Execution | `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `CreateRemoteThread`, `VirtualAllocEx`, `VirtualProtectEx`, `VirtualFreeEx`, `ResumeThread`, `GetExitCodeThread`, `CreateProcessW`, `TerminateProcess`, `ExitProcess`, `GetCurrentProcessId`, `GetCurrentProcess` | Cho thấy payload có đủ primitive để tạo tiến trình mới, thao tác bộ nhớ tiến trình đích và kích hoạt luồng thực thi từ xa. Đây là nhóm năng lực phù hợp với kết quả quan sát được khi mã độc chuyển hoạt động sang `svchost.exe`. |
| Memory / Loader | `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `VirtualQueryEx`, `OpenFileMappingW`, `MapViewOfFile`, `UnmapViewOfFile` | Hỗ trợ unpacking, giải nén, manual mapping, đổi quyền vùng nhớ sang `RWX/RX` và staging payload trong memory-mapped region. Đây chính là nền tảng kỹ thuật cho chuỗi loader đã được xác nhận trong debugger. |
| Multi-Threading / Sync / IOCP | `CreateThread`, `SleepEx`, `CreateEventW`, `SetEvent`, `ResetEvent`, `WaitForSingleObject`, `WaitForMultipleObjects`, `CreateIoCompletionPort`, `GetQueuedCompletionStatus`, `PostQueuedCompletionStatus` | Cho thấy payload có thể chạy theo mô hình agent đa luồng với cơ chế đồng bộ nội bộ và worker pool bất đồng bộ, thay vì chỉ là một executable tuyến tính đơn giản. |
| IPC (Named Pipe) | `CreateNamedPipeW`, `ConnectNamedPipe`, `DisconnectNamedPipe`, `GetOverlappedResult` | Gợi ý khả năng liên lạc giữa các thành phần hoặc giữa các tiến trình thông qua named pipe, phù hợp với thiết kế malware nhiều module hoặc điều phối nội bộ giữa loader và worker. |
| Registry (Persistence / Config) | `RegOpenKeyExW`, `RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW`, `RegEnumKeyExW`, `RegEnumValueW`, `RegDeleteValueW`, `RegCloseKey` | Hỗ trợ tạo persistence qua `Run key`, lưu cấu hình, đọc trạng thái hệ thống, liệt kê khóa/giá trị hiện có và xóa giá trị khi cần thay đổi cấu hình hoặc dọn hiện vật. |
| Service Configuration | `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`, `OpenServiceW`, `ChangeServiceConfigW`, `ChangeServiceConfig2W`, `QueryServiceStatusEx`, `EnumServicesStatusExW`, `DeleteService`, `CloseServiceHandle` | Cho thấy payload có khả năng thiết lập, sửa cấu hình, kích hoạt và quản lý `Windows service`. Điều này nhất quán với dấu vết service persistence đã được ghi nhận trong `HKLM\System\CurrentControlSet\Services`. |
| Token / Privilege Operations | `OpenProcessToken`, `GetTokenInformation`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `RevertToSelf`, `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `LookupAccountSidW`, `AllocateAndInitializeSid`, `SetTokenInformation` | Đây là tập API thường gặp khi malware cần nâng quyền, giả mạo ngữ cảnh đăng nhập, hoặc điều chỉnh đặc quyền để can thiệp sâu hơn vào service, registry hay các tiến trình có mức integrity cao. |
| Keylogging / Input Capture | `SetWindowsHookExW`, `CallNextHookEx`, `UnhookWindowsHookEx`, `GetAsyncKeyState`, `GetKeyState`, `GetForegroundWindow`, `GetWindowTextW`, `GetWindowThreadProcessId`, `SetTimer`, `KillTimer`, `DispatchMessageW`, `GetMessageW`, `TranslateMessage` | Cụm API này cho thấy payload có khả năng hook bàn phím, theo dõi cửa sổ foreground và duy trì message loop để phục vụ keylogging hoặc giám sát tương tác người dùng. |
| Screen Capture | `CreateDIBSection`, `CreateCompatibleDC`, `CreateCompatibleBitmap`, `GdiFlush`, `BitBlt`, `GetDeviceCaps`, `DeleteDC`, `DeleteObject`, `GetDIBits`, `CreateDCW`, `SelectObject` | Cho phép chụp nội dung màn hình hoặc cửa sổ, trích xuất bitmap và chuẩn bị dữ liệu hình ảnh để lưu cục bộ hoặc đẩy về C2. Đây là năng lực collection có giá trị cao trong bối cảnh RAT/spyware. |
| Environment Detection / Anti-Analysis | `VerifyVersionInfoW`, `GetVersionExW`, `GetSystemInfo`, `GlobalMemoryStatus`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `SetErrorMode` | Nhóm API này thường được dùng để fingerprint môi trường, kiểm tra phiên bản hệ điều hành, tài nguyên hệ thống hoặc đo độ trễ nhằm nhận biết sandbox/VM/debugger và thay đổi hành vi để né phân tích. |
| Network / Discovery / C2 | `InternetConnect`, `HttpOpenRequest`, `HttpSendRequestEx`, `WNetOpenEnum`, `WNetEnumResource`, `GetAdaptersInfo`, `gethostbyname`, `SQLDriverConnect`, `SQLExecDirect` | Kết hợp với quan sát động, nhóm API này cho thấy payload có khả năng liên lạc C2 qua web, liệt kê tài nguyên mạng, thu thập cấu hình mạng máy nạn nhân, và thậm chí tương tác với cơ sở dữ liệu nội bộ nếu môi trường mục tiêu cho phép. |


Quay trở lại với luồng phân tích từ `x32Dbg`, thay vì để hệ điều hành nạp file, mã độc sử dụng vòng lặp `memcpy` để tự ánh xạ (Manual Mapping) từng phân đoạn của tệp `PE` vào bộ nhớ ảo. Bằng cách tự xây dựng cấu trúc `PE` thủ công và sử dụng `header` giả, mã độc dễ dàng lẩn trốn các cơ chế giám sát hành vi nạp file thực thi tiêu chuẩn của Windows.

![image](/assets/images8/31.png)

Thấy được một vùng nhớ mới được cấp phát tại thanh ghi `EAX` là `021A1000`, ta tiến hành chạy hết vòng lặp kết hợp với `follow` vùng nhớ đó để ra được `payload` cuối cùng. Chạy xong, luồng thực thi quay lại với luồng của `McUtil.dll`. Thực hiện lệnh gọi cuối `call ecx` trước khi rơi vào trạng thái `Sleep`

![image](/assets/images8/33.png)

Tại thời điểm dump vùng nhớ, mã độc đã thực hiện xong quá trình giải mã trên bộ nhớ, cho phép ta thu thập được các IoC và chuỗi API ở dạng rõ (plaintext), cụ thể bao gồm:

![image](/assets/images8/42.png)

- Xác nhận máy chủ điều khiển (C2 Server): `asia.dcsvn.org`
- Giao thức: Sử dụng bộ thư viện WinInet `(InternetConnect, HttpOpenRequest, HttpSendRequestEx)` để truyền tải dữ liệu qua HTTP/HTTPS.
- Thám mã mạng: Các hàm `WNetOpenEnum`, `WNetEnumResource` cho phép liệt kê tài nguyên và máy trạm trong mạng nội bộ (`Lateral Movement`).
- Thu thập thông tin thiết bị: Sử dụng `GetAdaptersInfo` và `gethostbyname` để lấy cấu hình mạng và định danh máy.
- Duy trì quyền kiểm soát: Sử dụng `CreateProcess` và đường dẫn giả mạo `%AUTO%\McAfee` để thực thi mã từ xa và ẩn mình dưới danh nghĩa ứng dụng bảo mật.

### Luồng tái tạo mã độc

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
