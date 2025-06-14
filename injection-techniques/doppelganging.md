# Process Doppelgänging

💡 **Summary:**  
Process Doppelgänging is a stealthy code injection technique that combines elements of process hollowing with fileless execution via Windows Transactional NTFS (TxF).  
It allows attackers to run malicious payloads in memory without ever dropping a malicious file on disk.

---

## 🧠 Key Steps

1️⃣ **Create Transaction (TxF)**  
- The attacker opens a Windows file system transaction (`CreateTransaction`).

2️⃣ **Create and Write Malicious PE to Transacted File**  
- The attacker writes a PE image into a file within this transaction (`CreateFileTransacted`, `WriteFile`).  
- The file is not visible on disk.

3️⃣ **Create Section Object**  
- The malicious PE is mapped into memory using `NtCreateSection`.

4️⃣ **Rollback Transaction**  
- The transaction is rolled back (`RollbackTransaction`), deleting the file but leaving the section object in memory.

5️⃣ **Create Suspended Legitimate Process**  
- A clean process is started in suspended mode (`CreateProcess` with `CREATE_SUSPENDED`).

6️⃣ **Map Malicious Section into Process**  
- The malicious section is mapped (`NtMapViewOfSection`).

7️⃣ **Resume Process**  
- The process resumes, now running malicious code (`ResumeThread`).

---

## 🔍 Detection Ideas

- **TxF API abuse:** Rare in modern legitimate software — look for `CreateTransaction`, `CreateFileTransacted`, `RollbackTransaction`.  
- **Mismatched section and file:** Section objects that have no matching on-disk file.  
- **Suspended processes + unusual memory sections:** Suspicious section mappings after suspended process creation.  
- **Memory image mismatch:** The PE image in memory does not match the on-disk file of the process.

---

## 📊 Diagram

![Doppelgänging Flow](diagrams/doppelganging_flow.png)

---

## ⚡ References

- Original research: *Process Doppelgänging* (Black Hat 2017)  
- https://www.blackhat.com/us-17/briefings/schedule/index.html#process-doppelgnging-image-tampering-for-executing-arbitrary-code-6242  
- Windows API: [CreateTransaction](https://learn.microsoft.com/en-us/windows/win32/api/ktmw32/nf-ktmw32-createtransaction)

---

