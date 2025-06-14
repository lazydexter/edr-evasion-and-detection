# Transacted Hollowing

## 📌 What is Transacted Hollowing?

Transacted Hollowing is an advanced code injection technique that combines **process hollowing** with **Transactional NTFS (TxF)** to achieve stealth. It allows attackers to:

* Start a legitimate process in suspended mode.
* Hollow out (unmap) the original code sections.
* Map a malicious PE file (from a transacted file) into the process memory.
* Roll back the transaction, leaving no malicious file on disk.
* Resume the process so it executes attacker-controlled code while appearing legitimate.

## 🚀 Execution Flow

```
[SUSPENDED PROCESS: legit.exe loaded → base image points to legit.exe file]
       ↓ hollowing
[Original base image unmapped or cleared]
       ↓ section mapping
[Malicious PE section object (TxF) mapped into process]
       ↓
[Process resumes, runs attacker code]
```



## ⚡ Detection Logic Samples


* **Hunting tip:** Look for processes where `CreateTransaction` + `CreateFileTransacted` + `NtCreateSection` + `RollbackTransaction` happen in sequence with no file left on disk.


```

## 🎯 References

* [Process Doppelgänging and Transacted Hollowing explained](https://www.blackhat.com/docs/eu-17/materials/eu-17-Kogan-Process-Doppelganging-Using-Windows-Transactions-To-Inject-Code-Stealthily-wp.pdf)
* Malware analysis blogs
* Memory forensic frameworks (e.g., Volatility plugins)

---

✅ *This GitHub note is part of my study on process injection, hollowing, and stealth code execution techniques. Suggestions for improvement welcome!*
