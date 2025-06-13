# Classic CreateRemoteThread & APC Injection

## 📌 Concept

Both techniques inject code into a remote process and hijack its execution to run arbitrary code. The main difference lies in *how* execution is triggered:

| Technique | Execution Method | When Code Runs | Alertable Thread Needed? |
|------------|-----------------|----------------|-------------------------|
| CreateRemoteThread | Directly creates a new thread | Immediately | ❌ No |
| APC Injection | Queues code on existing thread | When thread is alertable | ✅ Yes |

---

## 🛠️ Shared APIs

| API | Purpose |
|------|---------|
| `OpenProcess` | Get handle to target process |
| `VirtualAllocEx` | Allocate memory in target process |
| `WriteProcessMemory` | Write code/shellcode to target |
| `LoadLibraryA` | (Optional) Inject DLL |

---

## 🚀 Classic CreateRemoteThread Flow

| Step | Description |
|-------|-------------|
| **1️⃣ Open Target Process** | `OpenProcess` for process handle |
| **2️⃣ Allocate Memory** | `VirtualAllocEx` for shellcode space |
| **3️⃣ Write Code** | `WriteProcessMemory` |
| **4️⃣ Start Thread** | `CreateRemoteThread` to run shellcode |

```cpp
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteShellcode, NULL, 0, NULL);


APC Injection Flow

| Step                             | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| **1️⃣ Open Target Process**      | `OpenProcess` for handle                                     |
| **2️⃣ Allocate Memory**          | `VirtualAllocEx`                                             |
| **3️⃣ Write Code**               | `WriteProcessMemory`                                         |
| **4️⃣ Get Thread Handle**        | `OpenThread`                                                 |
| **5️⃣ Queue APC**                | `QueueUserAPC`                                               |
| **6️⃣ Wait for Alertable State** | The thread must hit `SleepEx`, `WaitForSingleObjectEx`, etc. |

QueueUserAPC((PAPCFUNC)remoteShellcode, hThread, NULL);

🕵️ Detection Logic

**Shared Indicators**

Remote memory allocation + writes

Code execution in foreign process

Specific to CreateRemoteThread
New thread with start address in unusual memory

**Specific to APC**
Queueing APCs to unrelated threads

Threads forced into alertable state

🔎 **MITRE ATT&CK Mapping**
T1055.001 – CreateRemoteThread Injection

T1055.004 – APC Injection

🚩 **Limitations**
Technique	Limitation
CreateRemoteThread	Easier to detect due to direct thread creation
APC Injection	Relies on thread entering alertable state

📚 **References**
CreateRemoteThread docs
QueueUserAPC docs
MITRE T1055


