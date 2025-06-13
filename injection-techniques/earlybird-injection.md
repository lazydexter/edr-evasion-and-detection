# Early Bird Injection

## Concept

Early Bird Injection is an advanced process injection technique where the attacker injects malicious code into a newly created suspended process and queues an APC (Asynchronous Procedure Call) before the process runs any of its own code. This allows the malicious code to execute before the legitimate application logic begins, evading many defensive hooks.

---

## Step-by-Step Flow

| Step | Action                               | Purpose                                                     |
|-------|---------------------------------------|-------------------------------------------------------------|
| 1️⃣   | `CreateProcess` with `CREATE_SUSPENDED` | Starts target app in suspended mode (it won’t run yet).      |
| 2️⃣   | `VirtualAllocEx` + `WriteProcessMemory` | Allocates memory & injects shellcode into target process.    |
| 3️⃣   | `OpenThread` or get main thread handle  | Prepares to queue an APC.                                   |
| 4️⃣   | `QueueUserAPC`                        | Points the APC to run the malicious code.                   |
| 5️⃣   | `ResumeThread`                        | Wakes the thread; it hits the APC before the app runs main. |

---

## Normal QueueUserAPC Flow

In a traditional APC injection:

- The attacker targets an already running process (like explorer.exe or notepad.exe).
- Uses `OpenThread` to get a handle on a live thread.
- Allocates memory (`VirtualAllocEx`) and writes shellcode (`WriteProcessMemory`).
- Queues an APC (`QueueUserAPC`) to that thread.
- Waits for the thread to enter an alertable state (e.g., via `SleepEx`, `WaitForSingleObjectEx`).

---

## Why Early Bird Bypasses More

| 💡 Reason               | 🔍 Description                                                                 |
|-------------------------|-------------------------------------------------------------------------------|
| No `OpenThread` needed   | You're not touching external processes. You control the new process/thread. |
| No alertable wait needed | APC runs immediately on resume; no need for a thread to enter alertable state. |
| Hooks not present yet    | Code executes before EDR user-mode hooks or DLLs load.                       |
| No injection into live   | Avoids red flags of injecting into already-running sensitive processes.      |
| Timing                   | Code runs at process initialization, outside most EDR monitored windows.    |

---

## Detection Logic (EDR + SIEM Ideas)

### 🚩 EDR Detection Points
- Suspicious use of `CreateProcess` with `CREATE_SUSPENDED` flag.
- Immediate sequence of `VirtualAllocEx`, `WriteProcessMemory`, and `QueueUserAPC`.
- Queueing APCs to threads before any normal app code runs.
- Memory regions marked RX or RWX unexpectedly in early process stages.
- Lack of normal DLL load or startup sequence before code executes.

---

### 🔍 SIEM Detection Ideas
- Chain detection: suspended process → memory allocation + write → APC → resume.
- Outlier process combos: e.g., Office spawning suspended Notepad.
- RX/RWX memory creation patterns in processes that don’t need them.
- APC usage in unexpected processes or under unusual users.

---

## KQL Example Queries

### 1️⃣ Detect `CREATE_SUSPENDED` Process + Memory Ops + APC

```kql
DeviceProcessEvents
| where ActionType == "CreateProcess"
    and ProcessCommandLine contains "CREATE_SUSPENDED"
| join kind=inner (
    DeviceProcessEvents
    | where ActionType in ("VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC")
) on DeviceId, InitiatingProcessId
| summarize event_count = count(), actions = make_set(ActionType)
    by Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
| where array_length(actions) >= 2
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, actions, AccountName
