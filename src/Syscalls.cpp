#include "Syscalls.h"
#include <windows.h>

// Helper function to initialize syscall struct
BOOL InitializeSyscallStruct(SyscallStruct* St) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return FALSE;
    }

    // Resolve the addresses of syscalls using GetProcAddress
    St->NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    St->NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    St->NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    St->NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");
    St->NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    St->NtCreateProcess = (NtCreateProcess_t)GetProcAddress(hNtdll, "NtCreateProcess");
    St->NtSetInformationFile = (NtSetInformationFile_t)GetProcAddress(hNtdll, "NtSetInformationFile");  // Add NtSetInformationFile

    // Ensure all syscalls are loaded
    if (!St->NtAllocateVirtualMemory || !St->NtProtectVirtualMemory || !St->NtWriteVirtualMemory ||
        !St->NtQueueApcThread || !St->NtCreateSection || !St->NtCreateProcess || !St->NtSetInformationFile) {
        return FALSE;
    }

    return TRUE;
}
