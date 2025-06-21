# 💣 Shellcode Encryption

## 🧠 What is it?

Attackers use small pieces of code called **shellcode** to take control of a system. But writing that code clearly in a file will get flagged by antivirus.

So instead, they:
- 🔒 Encrypt the shellcode
- 🔓 Decrypt it only at runtime — inside memory (RAM)

> It's like hiding a knife in your backpack, only taking it out once you're inside the building — so metal detectors don’t catch it.

---

## ✅ Example

The attacker encrypts the shellcode using `XOR` or `AES`, and decrypts it in RAM like this:

```cpp
char encryptedShellcode[] = {...};  // XOR encrypted
Decrypt(encryptedShellcode);
VirtualAlloc(...)                   // Allocate memory
memcpy(...)                         // Copy decrypted shellcode
CreateThread(...)                   // Run it


KQL

DeviceProcessEvents
| where ProcessCommandLine has_any ("xor", "decrypt", "VirtualAlloc")


Sigma Rule

title: Encrypted Shellcode Behavior Detected
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'xor'
      - 'VirtualAlloc'
      - 'decrypt'
  condition: selection
level: medium
