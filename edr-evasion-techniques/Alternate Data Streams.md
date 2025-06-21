
---



```markdown
# 🗃️ Alternate Data Streams (ADS)

## 🧠 What is it?

Windows NTFS file system allows a file to have multiple “streams” of data. The main content is one stream, but attackers can hide extra data in another stream — completely invisible to normal tools like Explorer or even some antivirus engines.

> It's like writing secret notes in invisible ink. The page looks blank, but there's something hidden there.

---

## ✅ Simple Example

```bash
# Hiding malware in an ADS
echo "malicious code" > notepad.exe:hidden.txt

# This creates an alternate stream called "hidden.txt" inside notepad.exe

# To read it:
more < notepad.exe:hidden.txt


## KQL Detection

DeviceFileEvents
| where FileName contains ":"


##📦 Sigma Rule


title: Alternate Data Stream Usage Detected
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|contains: ":"
  condition: selection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1564.004



