#include <windows.h>
#include <winternl.h>
#include <cstdio>

#include "include/shadowcall.hpp"

int main() {
    LoadLibraryA("user32.dll");

    printf("[>] Testing shadow::call(MessageBoxA)...\n");
    int msgbox_result = shadow::call<int>(
        "user32.dll"_fnv1a64,
        "MessageBoxA"_fnv1a64,
        nullptr,
        "Hello World",
        "Demo",
        MB_OK | MB_ICONINFORMATION
    );
    printf("[+] MessageBoxA executed. User clicked button ID: %d\n\n", msgbox_result);

    printf("[>] Testing shadow::syscall (NtQueryInformationProcess)...\n");

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG return_length = 0;
    NTSTATUS status_query = shadow::syscall("NtQueryInformationProcess"_fnv1a64,
        -1,
        static_cast<PROCESSINFOCLASS>(0),
        &pbi,
        static_cast<ULONG>(sizeof(pbi)),
        &return_length
    );

    if (status_query == 0x00000000) {
        printf("[+] NtQueryInformationProcess success!\n");
        printf("    |- Process ID (PID): %Iu\n", pbi.UniqueProcessId);
        printf("    |- PEB Base Address: 0x%p\n\n", pbi.PebBaseAddress);
    } else
        printf("[-] NtQueryInformationProcess failed with NTSTATUS: 0x%08X\n\n", status_query);

    printf("[>] Testing shadow::syscall(NtAllocateVirtualMemory)...\n");

    PVOID allocated_memory = nullptr;
    SIZE_T region_size = 0x1000;

    NTSTATUS status_alloc = shadow::syscall("NtAllocateVirtualMemory"_fnv1a64,
        -1,
        &allocated_memory,
        static_cast<ULONG_PTR>(0),
        &region_size,
        static_cast<ULONG>(MEM_COMMIT | MEM_RESERVE),
        static_cast<ULONG>(PAGE_READWRITE)
    );

    if (status_alloc == 0) {
        printf("[+] NtAllocateVirtualMemory success!\n");
        printf("    |- Allocated Address: 0x%p\n", allocated_memory);

        const char* test_string = "Memory mapped securely via syscalls.";
        memcpy(allocated_memory, test_string, 37);

        printf("    |- Verified Memory Content: \"%s\"\n", static_cast<char*>(allocated_memory));
    } else
        printf("[-] NtAllocateVirtualMemory failed with NTSTATUS: 0x%08X\n", status_alloc);

    return 0;
}