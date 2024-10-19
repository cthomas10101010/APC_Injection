#include "Syscalls.h"
#include <windows.h>
#include <stdio.h>

// Initialize the syscall function pointers
BOOL InitializeSyscallStruct(PSyscallStruct St) {
    // Use ANSI string for GetModuleHandleA (No 'L' prefix for wide-char)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] GetModuleHandleA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Fetch the addresses of the syscalls
    St->NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    St->NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    St->NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    St->NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");

    // Check if all necessary syscalls were found
    if (!St->NtAllocateVirtualMemory || !St->NtProtectVirtualMemory || !St->NtWriteVirtualMemory || !St->NtQueueApcThread) {
        printf("[!] Could Not Get Required Syscalls.\n");
        return FALSE;
    }

    return TRUE;
}
