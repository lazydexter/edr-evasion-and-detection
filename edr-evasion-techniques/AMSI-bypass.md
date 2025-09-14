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
