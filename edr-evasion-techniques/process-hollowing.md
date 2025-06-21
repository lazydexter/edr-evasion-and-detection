
---

# 🕳️ Process Hollowing

## What is Process Hollowing?

Process hollowing is a technique used by attackers to:
✅ Start a legitimate process in **suspended mode**
✅ Remove (or hollow out) the legitimate code in memory
✅ Replace it with **malicious code** (e.g., shellcode, a PE payload)
✅ Resume the process so that the malicious code runs **under the identity of the trusted process** (e.g., `notepad.exe`)

➡ **Why attackers use it?**
It helps evade security tools that rely on process names, signatures, or paths — because the process *looks* legitimate at a glance.

---

## ⚙️ Process Hollowing: Step-by-Step

| Step | Action                                                 | Purpose                                                                                           |
| ---- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| 1️⃣  | `CreateProcess` with `CREATE_SUSPENDED`                | Launch a legitimate process (e.g., `notepad.exe`) but pause it before execution starts.           |
| 2️⃣  | Get thread & process handles                           | Get the handles needed to control the process and its primary thread.                             |
| 3️⃣  | Query image base address (`NtQueryInformationProcess`) | Find where in memory the process's legitimate code is loaded.                                     |
| 4️⃣  | Unmap legitimate image (`NtUnmapViewOfSection`)        | Remove the original executable's code from memory (hollow it out).                                |
| 5️⃣  | Allocate memory for malicious code (`VirtualAllocEx`)  | Reserve space inside the hollowed process for your payload.                                       |
| 6️⃣  | Write malicious code (`WriteProcessMemory`)            | Inject your shellcode or PE image into the process memory.                                        |
| 7️⃣  | Set thread context                                     | Update the entry point (e.g., via `SetThreadContext`) so execution starts at your malicious code. |
| 8️⃣  | Resume the thread (`ResumeThread`)                     | The process starts running — but it’s executing your payload, not its original code.              |

---
![image](https://github.com/user-attachments/assets/c7d296d7-059b-455d-b996-f6e22338e2ef)

![image](https://github.com/user-attachments/assets/b8f640d9-8006-4d94-b4c2-2c2a75332703)




## ⚡ Why This Helps Attackers Evade Detection

* The process still **looks legitimate** (e.g., signed binary, known path).
* Security tools that check **file names or signatures** may trust it.
* The actual payload runs silently **inside the hollowed process**.

---

## 🕵️ EDR / Detection Points

➡ **Typical indicators defenders look for:**

* Use of `CreateProcess` with `CREATE_SUSPENDED`
* Calls to `NtUnmapViewOfSection` (rare in normal apps)
* Mismatch between loaded image in memory vs. image on disk
* Unusual memory protections (e.g., `PAGE_EXECUTE_READWRITE` in areas that shouldn’t be writable/executable)
* Abnormal `SetThreadContext` usage

---

## 💡 Example Detection Logic (KQL)

```kql
DeviceProcessEvents
| where InitiatingProcessCommandLine contains "CREATE_SUSPENDED"
| where FileName in~ ("notepad.exe", "explorer.exe", "svchost.exe")
| summarize count() by InitiatingProcessFileName, FileName, bin(Timestamp, 1h)
```

👉 Combine this with memory-related events or API telemetry (if available).

---

## 🔄 What is Relocation?

When an executable is built, it’s assigned a **preferred image base address** (e.g., `0x00400000` for `notepad.exe`).

If that address is already used (e.g., by another loaded DLL):

* The OS loads the executable at a different base address.
* The loader **applies relocations**: it adjusts addresses in the code so everything points to the right place.

➡ **In Process Hollowing:**

* Attackers try to map their malicious code at the original base address to avoid needing relocations.
* If they can’t, they must handle relocation themselves, or risk a crash.

---

SIGMA 

title: Process Hollowing Behavior Detected
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'WriteProcessMemory'
      - 'NtUnmapViewOfSection'
      - 'ResumeThread'
  condition: selection
level: high
tags:
  - attack.t1055.012
  - attack.defense_evasion



