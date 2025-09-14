# AMSI Bypass Techniques

## 🎯 Objective
Demonstrate and document common techniques used to bypass the **Antimalware Scan Interface (AMSI)** in Windows.  
These techniques are frequently leveraged by attackers and red team operators to execute obfuscated payloads and scripts without being blocked by AV/EDR.

---

## 🧩 How AMSI Works
1. Script or payload is loaded into memory (e.g., PowerShell command, macro, VBScript).
2. Before execution, the content is passed to **amsi.dll → AmsiScanBuffer()**.
3. amsi.dll forwards the content to the registered antivirus/EDR engine (e.g., Microsoft Defender).
4. If malicious → execution is blocked. If clean → execution proceeds.

---

## 🚀 Common Bypass Techniques

### 1. **Patching `AmsiScanBuffer` in Memory**
- Overwrite the function prologue so it always returns `AMSI_RESULT_CLEAN`.
- Example patch bytes:  
  ```assembly
  48 31 C0    ; XOR RAX, RAX
  C3          ; RET


4. ETW / Context Manipulation

Overwrite or nullify the HAMSICONTEXT handle.

Makes calls to AmsiScanBuffer() silently fail.

5. DLL Hollowing / Manual Mapping

Load a custom or hollow amsi.dll into memory.

Replace the system’s version with one that always returns clean results.

6. Dynamic Instrumentation (Frida)

Hook into AmsiScanBuffer dynamically using Frida or similar tooling.

Override return values at runtime.

⚔️ Red Team Ops

Use these bypasses only in controlled lab environments.

Example scenarios:

Execute obfuscated PowerShell payloads without Defender flagging.

Test whether an EDR product detects AMSI tampering.

🛡️ Detection Opportunities

Defenders can hunt AMSI bypass attempts by:

Monitoring memory patching of amsi.dll.

Detecting PowerShell commands or C# code setting amsiInitFailed = true.

Looking for unsigned modules replacing amsi.dll.

Event Tracing for Windows (ETW) anomalies.

Unusual use of WriteProcessMemory targeting amsi.dll.

MITRE ATT&CK Mapping:

T1562.001 – Impair Defenses: Disable or Modify Security Tools

T1055 – Process Injection (when used to patch memory)

T1620 – Reflective Code Loading

📚 References

Microsoft Docs – Antimalware Scan Interface

MITRE ATT&CK: T1562.001 – Impair Defenses

Red Team AMSI Bypass Techniques
