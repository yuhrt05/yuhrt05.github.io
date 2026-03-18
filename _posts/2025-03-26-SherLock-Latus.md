---
title: "HackTheBox: Latus"
date: 2025-05-31 14:22:00 +0700
categories: [SherLock]
tags: [Hackthebox, forensics]
image: /assets/images3/banner.jpg
toc: true
layout: post
---

## _Latus_ _(Forensics)_

![image](assets/images3/1.png)

## _Solution_

#### Q1. When was the last failed logon attempt using emman.t user? (UTC)

Khi gặp câu hỏi về `loggin` thì mình sẽ ưu tiên check trong log `Security` với ID `4625` nhưng vào kiểm tra thì không có. Mình sẽ dùng  `hayabusa` để xem những `log` khả nghi

![image](assets/images3/2.png)

Thấy được 1 `alert` ở đầu về việc `Log Cleared`, nên khả năng cao các sự kiện `failed logon` trước đó đã bị xóa dấu vết. Mình sẽ chuyển hướng sang check `Registry` cụ thể là tại file `SAM`

Thông thường khi nhắc đến `SAM` thì thường nghĩ đến chức năng chính là lưu trữ `user account`, nhưng ngoài đó ra thì nó còn lưu thêm các lần `last failed login`, `last password change`,... Và file `SAM` lưu trữ nó dưới dạng 1 `offset` trong `F` (một blob nhị phân) theo định dạng `windows filetime`. Nên nếu dùng `regedit.exe` mặc định của `windows` sẽ không đọc được bình thường. Vậy ở đây ta cần dùng `RegistryExpoler`

![image](assets/images3/3.png)

`Answer: 2024-06-26 07:24:35`

#### Q2. What are the first 3 IP addresses that emman.t connected to using Remote Desktop (RDP)?

Câu này check trong key `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default` của chính user `emman.t`

![image](assets/images3/4.png)

`Answer: 192.168.86.250,192.168.25.128,192.168.25.131`

#### Q3. What is the destination username used to remote desktop to for the first time on 2024-06-20 16:01:05 UTC?

Vẫn trong key đó ta có được `username`

![image](assets/images3/5.png)

`Answer: tommyxiaomi`

#### Q4. What is the destination IP address of the last Remote Desktop (RDP) session?

Vẫn trong câu trên

`Answer: 192.168.70.133`

#### Q6. When was the last time the Remote Desktop Connection application was executed? (UTC)

Hỏi thời gian thực thi thường thì mình sẽ check trong `prefetch`

![image](assets/images3/6.png)

`Answer: 2024-06-28 13:56:48`

#### Q12. When was the event log deleted by the attacker? (UTC)

Ở câu 1 mình đã kiểm tra bằng `hayabusa`, vì UTC nên phải trừ 7

![image](assets/images3/7.png)

`Answer: 2024-06-28 14:03:25`

#### Q10. What is the size of the remote desktop configured?

Câu này mình sẽ check trong file `Default.rdp`, file này được tạo tự động mỗi khi ta kết nối bằng `Remote Desktop` mặc định của windows, nó lưu trữ 1 số thông tin sau

| Thông tin                                           | Mô tả                                                           |
| --------------------------------------------------------- | --------------------------------------------------------------- |
| **full address\:s:**                                      | Địa chỉ IP hoặc hostname mà người dùng kết nối gần nhất       |
| **username\:s:**                                          | Tên đăng nhập (thường là `.\username` hoặc `domain\username`)   |
| **screen mode id\:i:**                                    | Chế độ hiển thị (1: Window, 2: Fullscreen)                      |
| **desktopwidth\:i / desktopheight\:i**                    | Kích thước màn hình                                             |
| **compression\:i / audio mode\:i / redirectclipboard\:i** | Các cài đặt nâng cao (nén, âm thanh, clipboard...)              |
| **authentication level\:i:**                              | Mức độ xác thực (0-3)                                           |
| **password 51\:b:**                                       | Một chuỗi được mã hóa (không phải password raw), dùng nội bộ |


![image](assets/images3/8.png)

`Answer: 1920:1080`

#### Q9. When did the attacker disconnect the last Remote Desktop (RDP) session? (UTC)

Check trong phần `properties` của file `default.rdp` đó

![image](assets/images3/9.png)

`Answer: 2024-06-28 13:51:03`

#### Q13. What time did attacker disconnect session to 192.168.70.129? (UTC)

Vì có nhiều IP, nên lúc làm thì mình check xem IP của máy mình đang điều tra

![image](assets/images3/10.png)

IP máy chính là `192.168.70.129` nên ta có thể điều tra trong `Security.evtx`

Mình lọc riêng `logged off` ra nhưng có tận 6 cái nên mình thử nhập bừa thì nó đúng ngay cái đầu tiên

![image](assets/images3/11.png)

Điều tra kĩ hơn thì biết được trước khi thực hiện đăng xuất thì `attacker` đã thực hiện xóa `log` nên thấy khá hợp lí

![image](assets/images3/12.png)

#### Q7. When was the last time the Remote Desktop Connection application was terminated? (UTC)

Có 1 so sánh nhỏ tại các vị trí lưu thời gian khi chương trình được thực thi, kết thúc,... 

| **Dữ liệu**     | **Thời gian ghi nhận**         | **Cách khởi chạy**             | **Ghi lại** | **Ghi thời gian kết thúc?** |
|----------------|--------------------------------|--------------------------------|-------------|------------------------------|
| **Prefetch**   | Khi chương trình được nạp      | Bất kỳ                         | ✅ Có       | ❌ Không                     |
| **UserAssist** | Khi người dùng tương tác để mở | Phải có tương tác người dùng   | ✅ Có       | ❌ Không                     |
| **BAM**        | Khi process kết thúc   | Bất kỳ                         | ✅ Có       | ✅ Có                        |

Từ đây ta thấy được thời gian đúng sẽ làm nằm trong file `BAM` theo path `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID####\`, liên quan đến `Remote Desktop` nên check file `mstsc.exe`

![image](assets/images3/13.png)

`Answer: 2024-06-28 14:01:26`

#### Q11. What tool did attacker use to discover the network after moving laterally to 192.168.70.133?

Trước khi làm thì đã thử khá nhiều tool phổ biến nhưng không đúng

Nên mình có hỏi một người bạn và may mắn là ông bạn này đã done nó vào hồi tháng 10 năm ngoái, ~~quen từ giải Cyber Apocalypse~~ 🙊

![image](assets/images3/14.png)

Đại loại là khi sử dụng `RDP` để kết nối tới 1 máy khác thì `Windows` sẽ sử dụng cơ chế `Bitmap Caching` để tăng tốc độ hiển thị, thay vì phải tải lại toàn bộ giao diện đồ hoạ từ máy đích thì các hình ảnh (icon, cửa sổ, nút...) được cache cục bộ dưới dạng bitmap.

Vị trí Cache: `C:\Users\AppData\Local\Microsoft\Terminal Server Client\Cache\`, ta sẽ sử dụng tool [này](https://github.com/ANSSI-FR/bmc-tools) để lấy hình ảnh. Mình thấy tool quen vl tại trước cũng có giải nào đó mình dùng đến nó rồi

![image](assets/images3/15.png)

Nhiều vlon, giờ ngồi mò thôi

![image](assets/images3/16.png)

Thấy được 1 lệnh curl tool `Netbscanner`, mình thấy là ngồi rảnh mà ghép hết đống đó là cũng hình dung được phần nào kịch bản của attacker =))

`Answer: NetBScanner`

#### Q5. emman.t is very careless in always saving RDP credentials to connect to other hosts, so we believe that attacker somehow leaked them. Please confirm credentials of the server with ip 192.168.70.133 that was leaked?

Câu này khá khó và mình cũng phải nhờ đến sự trợ giúp của anh bạn `luminary` thì mới làm được

Ở đây mình sẽ phải dùng đến công cụ `DataProtectionDecryptor`.

Nói 1 chút là DPAPI:

`DPAPI (Data Protection API) là một thành phần cốt lõi trong hệ điều hành Windows dùng để mã hóa và giải mã dữ liệu nhạy cảm như mật khẩu, chứng chỉ, khóa bảo mật, và token. Nó cực kỳ quan trọng trong lĩnh vực digital forensics và malware analysis, vì nhiều phần mềm – kể cả Windows và bên thứ ba – đều dựa vào DPAPI để bảo vệ dữ liệu quan trọng.`

| Dữ liệu                                      | Địa chỉ                                               | 
| -------------------------------------------- | ------------------------------------------------------- 
| Trình duyệt Edge, Chrome, IE (login info)  | `Login Data`, `Vault`, `Credential Manager`             | 
| RDP `.rdp` file (`password 51:b`)          | Trong file cấu hình RDP                                 | 
| Wi-Fi password                             | SYSTEM hive hoặc plaintext sau khi giải mã              | 
| Windows Vault (`Policy.vpol`, `.vcrd`)     | AppData\Local                                           | 

Để dùng được tool mình cần 3 thành phần sau 
- Master Key: Được lưu tại `C:\Users\<user####\AppData\Roaming\Microsoft\Protect\<SID####\`
- Credential Store: `C:\Users\<user####\AppData\Local\Microsoft\Credentials\` (Đây là file chứa dữ liệu chính)
- SYSTEM + SECURITY hive: `\Windows\System32\config`
- Password user: Mật khẩu khi đăng nhập vào máy

3 thứ đầu mình có thể lấy được từ file `.ad1`, còn duy nhất cái cuối là `Password user`. Trong lúc làm, như mọi khi mình thường ngó qua `Console History`

![image](assets/images3/17.png)

Có thể thấy được 1 lệnh tạo tài khoản mới với tên user là `emman` và password là `emman2024` và một lệnh đổi tên từ một tài khoản đặc biệt là `IEUser` thành `emman.t` (Mà emman.t mới là user cần điều tra) nên khá tiếc là chưa có được `password` từ những thông tin trên. 

Hướng tiếp theo sẽ là đi crack password và may mắn là đã có 1 giải mình có học được về cái này rồi tại [đây](https://github.com/dxurt/CTF/tree/main/Midnight%20Flag%20CTF), Làm y hệt theo challenge `Blackdoor` là được

![image](assets/images3/18.png)

Lấy NThash đi crack, ra được `password` lại chính là `password` của thằng `emman` =))

![image](assets/images3/19.png)

Giờ mình sẽ đi trích xuất hết các thành phần cần để decrypt, nhưng mình cũng chưa hiểu tại sao mình export all cái `cred` thì nó lại kh lưu nên mình phải save từng cái một thì lại dược

![image](assets/images3/20.png)

![image](assets/images3/21.png)

`Answer: Administrator:C@mv@0s3rv3r`