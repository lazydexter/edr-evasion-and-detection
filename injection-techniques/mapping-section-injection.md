
# Mapping Section Injection

## 🔍 What is Mapping Section Injection?

**Mapping Section Injection** (also called **Section Object Injection**) is a stealthy process injection method where the attacker creates a memory section (a shared memory object), maps it into both the attacker’s and the target process, and writes malicious code into it.

👉 The benefit? The malicious code exists in shared memory — this can look less suspicious because Windows often uses shared memory for legitimate purposes.

---

## 🧠 How it works (Simple + Technical view)

👉 **Layman’s analogy:**
Imagine two people sharing the same notebook. One quietly writes a hidden message into the notebook. When the other person reads it, they unknowingly read the hidden message as if it was their own.

👉 **Technical flow:**

1️⃣ The attacker uses `NtCreateSection` / `CreateFileMapping` to **create a shared memory section**.

2️⃣ They map this section into **both their own process** and the **target process** (e.g., `explorer.exe`) using `NtMapViewOfSection` / `MapViewOfFile`.

3️⃣ The attacker writes their **shellcode** into this shared memory.

4️⃣ They create a thread in the target process (`CreateRemoteThread`) to execute the malicious code residing in the mapped section.

---

## 🚩 Detection logic (EDR + SIEM ideas)

| Detection Point                                    | What to Look For                                        |
| -------------------------------------------------- | ------------------------------------------------------- |
| 📌 `NtCreateSection` + `NtMapViewOfSection` combo  | Suspicious when one process maps a section into another |
| 📌 Shared sections containing executable shellcode | Rare in normal apps                                     |
| 📌 `CreateRemoteThread` targeting mapped memory    | Thread start address inside shared section              |

---

## ✅ Example KQL detection ideas

```kql
DeviceProcessEvents
| where ActionType == "CreateRemoteThread called"
| where RemoteThreadStartAddressType == "Mapped Section"
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcessFileName, RemoteThreadStartAddress
```

```kql
DeviceProcessEvents
| where ActionType has "NtCreateSection" or ActionType has "NtMapViewOfSection"
| project Timestamp, DeviceName, InitiatingProcessFileName, ActionType
```

👉 These queries should be tuned to your environment to minimize false positives.

---

## 💡 Why attackers like Mapping Section Injection

* Uses shared memory — harder to detect than fresh executable memory.
* Can avoid some EDR hooks because code is executed from legitimate-looking memory.
* No direct `WriteProcessMemory` into the target process.

---

