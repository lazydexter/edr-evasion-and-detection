# 🧵 Native API Injection

## 🧠 What is it?

Most security tools monitor common Windows APIs like `CreateRemoteThread` or `VirtualAlloc`.

But attackers can bypass these by using **lower-level "Native APIs"** like `NtWriteVirtualMemory` and `NtCreateThreadEx`, which talk directly to Windows' core — and are often **not monitored as closely**.

> It’s like speaking directly to the kernel instead of going through reception. No one notices unless they’re specifically watching.

---

## ✅ Simple Explanation

- Instead of using the usual APIs (which are noisy and visible), attackers resolve the **"Nt" APIs** dynamically.
- They **inject malicious code into a process** using these raw APIs — often avoiding detection by EDRs.

---

## 🧪 Real-World Behavior

```cpp
// Instead of CreateRemoteThread:
NtCreateThreadEx(...); 

// Instead of WriteProcessMemory:
NtWriteVirtualMemory(...);


## KQL:

DeviceProcessEvents
| where ProcessCommandLine has_any ("NtCreateThreadEx", "NtWriteVirtualMemory")

## SIGMA

title: Native API Injection Detected
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'NtCreateThreadEx'
      - 'NtWriteVirtualMemory'
  condition: selection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1055.004






