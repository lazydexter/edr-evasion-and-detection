
 String and API Obfuscation

## 🧠 What is it?

Obfuscating sensitive strings (like `VirtualAlloc`, URLs, or shellcode) by encoding (Base64/XOR), splitting, or hashing, to avoid detection by AV/EDR engines that rely on static signatures.

Attackers want to hide sensitive words (like VirtualAlloc, CreateRemoteThread) from antivirus tools.
Instead of writing them directly in the code, they scramble or hide them — so they won’t get caught by signature scanners.

## 🎯 Why it works

Static detection engines rely on recognizable strings. By changing those strings dynamically or hiding them, malware becomes harder to scan or flag during analysis.

## 🕵️ Detection Strategy

- Monitor use of `GetProcAddress`, `LoadLibrary` after memory allocations
- Watch for Base64 decoding, string concatenation, XOR loops in scripting engines
- Flag uncommon combinations in PowerShell, cmd, or compiled binaries

## 🔍 KQL Query (Microsoft Defender)

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("xor", "base64", "decode", "GetProcAddress", "LoadLibrary")
| where FileName has_any ("powershell.exe", "cmd.exe", "wscript.exe")

Sigma 

title: Suspicious String or API Obfuscation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'xor'
      - 'base64'
      - 'decode'
      - 'GetProcAddress'
      - 'LoadLibrary'
  condition: selection
level: low
tags:
  - attack.defense_evasion
  - attack.t1027




