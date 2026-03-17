---
title: "Midnight Flag CTF 2026"
date: 2026-02-16 03:00:00 +0700
categories: [CTF, Midnight Flag CTF]
tags: [Threat Hunting, Log analysis]
image: /assets/images10/banner.png
toc: true
layout: post
---

![image](assets/images10/7.jpg)

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

![image](assets/images10/1.png)

- Xuất hiện một truy vấn lạ sử dụng tính năng Expressions: `"expression":"SELECT content FROM read_blob('/etc/passwd')"`
- Sau đó attacker thực hiện tiếp truy vấn đến tệp tin mục tiêu: `"expression":"SELECT content FROM read_blob('/var/lib/grafana/ctf/secret.csv')"`

Từ đây xác định được, dữ liệu bị rò rỉ là `secret.csv`

Nhận thấy tiếp, hàm `read_blob` là hàm đặc trưng của `DuckDB`, đây là một engine phân tích dữ liệu thường được tích hợp làm plugin xử lý biểu thức trong các phiên bản của  `Granfa`. Việc cho phép thực thi `read_blob` trực tiếp từ giao diện người dùng cho thấy một lỗ hổng nghiêm trọng trong việc kiểm soát đầu vào

Dựa trên các yếu tố vừa phân tích, tiến hành search lỗ hổng trên gg

![image](assets/images10/2.png)

- Vuln được xác định với mã định danh: `CVE-2024-9264`
- Lỗ hổng cho phép người dùng có quyền `Viewer` trở lên thực thi các truy vấn `DuckDB` tùy ý, dẫn đến đọc tệp hệ thống hoặc thực thi `RCE` nếu các extension của DuckDB được kích hoạt

#### B2: Xác định nguồn gốc và danh tính

Tiến hành trace ngược lại các dòng log được thực thi lệnh xoay quanh việc rò rỉ dữ liệu từ Bước 1, ta thu thập được các IoCs

![image](assets/images10/3.png)

- Địa chỉ IP nguồn: `85.215.144.254`
- Công cụ: `python-requests/2.31.0` - Dấu hiệu của việc sử dụng script tự động, không phải người dùng tương tác qua trình duyệt
- Mã người dùng: `userID=5`

#### B3: Đối chiếu cơ sở dữ liệu

Để xác định `userID=5` là ai, tiến hành phân tích tệp grafana.db bằng SQLite:

![image](assets/images10/4.png)

=> user thực hiện malicious actions là `editor2`

`Flag: MCTF{CVE-2024-9264:/var/lib/grafana/ctf/secret.csv:85.215.144.254:editor2}`

# POST-MORTEM ARTIFACTS SERIES

#### Có tổng 3 challenge, solve được 1 challenge thì mới mở challenge tiếp theo

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

`Flag: MCTF{constrained-delegation_PURGE-SRV2_43:11}`
## POST-MORTEM ARTIFACTS (3/3)

### Description

![image](assets/images10/6.jpg)

### Solution

`Flag: MCTF{sloomis_16_51:56}`

## Gh0st_1n_7h3_G1t

### Solution

`Flag: MCTF{Th1S_Is_Y0uR_f7rst_P@rt0x_F1n@l_P4rt$}`