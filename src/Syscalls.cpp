#include <windows.h>
#include "Syscalls.h"

// Define STATUS_UNSUCCESSFUL if it's not included
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)  // Define the error code for NTSTATUS
#endif

// Custom function to call NtAllocateVirtualMemory syscall
NTSTATUS NtAllocateVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    PSIZE_T regionSize,
    ULONG allocationType,
    ULONG protect
) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return STATUS_UNSUCCESSFUL; // If we cannot get ntdll.dll, return failure.
    }

    // Get the address of NtAllocateVirtualMemory from ntdll.dll
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    if (!pNtAllocateVirtualMemory) {
        return STATUS_UNSUCCESSFUL; // If we cannot find the syscall, return failure.
    }

    // Now call NtAllocateVirtualMemory
    return pNtAllocateVirtualMemory(processHandle, baseAddress, 0, regionSize, allocationType, protect);
}
