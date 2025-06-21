# 🧬 Process Doppelgänging

## 🧠 What is it?

This technique uses a weird feature of Windows called the **Transaction File System (TxF)** — it lets you change a file without actually saving it to disk.

Attackers use this to run malware from a **"ghost file"** that never really exists on disk, so AVs can’t scan it.

> It's like walking into a building using a blueprint that was never printed — you’re there, but there’s no record of your path.

---

## ✅ Example (Layman View)

1. Attacker creates a "ghost" version of a legitimate file.
2. Modifies it in memory — fills it with malicious code.
3. Executes it through the Windows process loader.
4. The file never gets saved — so AV can't inspect it.

---

## 🛡️ Blue Team Tip

- TxF is rarely used — monitor for calls to `CreateTransaction`, `CreateFileTransacted`, etc.
- Look for processes with no backed file on disk but still executing.

---

## 🔍 KQL Example

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("CreateTransaction", "CreateFileTransacted", "RollBackTransaction")


title: Suspicious Process Doppelgänging Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'CreateTransaction'
      - 'CreateFileTransacted'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1055.013


