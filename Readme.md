Original idea to create a section with SEC_NO_CHANGE for syscalls: https://github.com/colby57/sec_no_syscalls

example.cpp output:
```
[>] Testing shadow::call(MessageBoxA)...
[+] MessageBoxA executed. User clicked button ID: 1

[>] Testing shadow::syscall (NtQueryInformationProcess)...
[+] NtQueryInformationProcess success!
    |- Process ID (PID): 19020
    |- PEB Base Address: 0x0000003B36816000

[>] Testing shadow::syscall (NtAllocateVirtualMemory)...
[+] NtAllocateVirtualMemory success!
    |- Allocated Address: 0x000001B81FBE0000
    |- Verified Memory Content: "Memory mapped securely via syscalls."
```