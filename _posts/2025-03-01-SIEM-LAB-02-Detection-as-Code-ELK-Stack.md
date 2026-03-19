---
title: "SIEM LAB 02: Xây dựng hệ thống Detections as Code (DaC) mini với ELK Stack"
date: 2026-03-01 03:00:00 +0700
categories: [SIEM LAB]
tags: [ELK Stack, Detections as Code, Python Scripting, Elastic Security, Sigma Rules, BotTelegram]
image: /assets/images11/DaC.png
toc: true
layout: post
---

## Mô hình triển khai

Hệ thống được thiết kế theo tư duy **Detections as Code**, nhằm chuẩn hóa việc xây dựng, kiểm thử và triển khai các Sigma Rules giống như quy trình phát triển phần mềm. Toàn bộ pipeline từ viết rule → kiểm thử → triển khai → giám sát → cảnh báo đều được tự động hóa, đảm bảo tính nhất quán, khả năng mở rộng và dễ audit.

---

## Workflows

![image](/assets/images11/Luong_chi_tiet.png)


### 1. Management Layer (Tầng quản lý mã nguồn)

Đây là nơi đóng vai trò trung tâm cho toàn bộ lifecycle của detection:

- Tất cả Sigma Rules được lưu trữ dưới dạng **YAML** trong Git repository.
- Áp dụng workflow chuẩn:
  - Developer viết rule → push lên `dev branch`
  - Thực hiện review → merge vào `main branch`
- Mỗi thay đổi đều có version control:
  - Dễ dàng rollback khi rule gây false positive
  - Audit lịch sử thay đổi (ai sửa, sửa gì, khi nào)

### 2. CI/CD Pipeline (Triển khai tự động)

Pipeline được thiết kế tách biệt **Dev** và **Prod**, đảm bảo an toàn:

#### Luồng Dev
- Khi có push vào `dev branch`:
  - GitHub Actions Dev được trigger
  - Thực hiện:
    - Validate Sigma Rule (syntax, logic)
    - Convert sang format Elasticsearch (EQL / DSL)
    - Push vào **Kibana Dev Space** thông qua API

#### Luồng Prod
- Khi PR được merge vào `main branch`:
  - GitHub Actions Prod chạy
  - Deploy rule sang **Kibana Prod Space**
  - Áp dụng cho môi trường production

#### Các thành phần chính
- Rule validation
- Sigma → Elastic conversion
- API push đến Kibana
- Phân tách môi trường rõ ràng

**Lợi ích:**
- Tránh deploy rule lỗi vào production
- Test trước ở Dev → giảm false positive
- Chuẩn hóa quy trình release detection

### 3. SIEM Layer (Elastic Stack)

Đây là nơi thực thi detection thực tế:

### Thành phần chính:
- **Kibana Dev Space / Prod Space**
  - Quản lý rule theo từng môi trường
  - Cho phép tuning detection riêng biệt

- **Detection Engine**
  - Chạy các rule đã được deploy
  - Thực hiện pattern matching trên log

- **Elasticsearch Index**
  - Lưu trữ log từ nhiều nguồn:
    - Windows Event Logs
    - Sysmon
    - Network logs
    - Application logs

### 4. Alerting & Automated Monitoring (Tự động hóa cảnh báo)

Module này giúp chuyển detection thành hành động thực tế:

#### Python Alert Monitor
- Polling liên tục vào Elasticsearch
- Lấy alert mới theo interval (ví dụ: mỗi 30s)

#### Xử lý alert
- **Deduplication**
  - Loại bỏ alert trùng lặp
  - Giảm noise cho SOC

- **Filter / Severity**
  - Phân loại mức độ:
    - Low / Medium / High / Critical
  - Cho phép ưu tiên xử lý

- **Formatting**
  - Convert alert sang HTML / Markdown
  - Hiển thị rõ: Rule name/Host/User/Timeline/IOC

#### Notification
- Gửi qua Telegram Bot API:
  - Realtime alert
  - Dễ tích hợp với SOC team
- Có thể mở rộng:
  - Slack
  - Email
  - SOAR platform

## Mã nguồn 

Toàn bộ script Python, cấu hình Pipeline và hướng dẫn triển khai chi tiết có tại:

### GitHub Repository: [![GitHub Repo](https://img.shields.io/badge/GitHub-SIEM--Automation--Project-blue?logo=github)](https://github.com/yuhrt05/SIEM-Automation-Project)
