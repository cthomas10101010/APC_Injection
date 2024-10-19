#pragma once
#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

// Declaration of NtAllocateVirtualMemory
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

// Custom function to call NtAllocateVirtualMemory syscall
NTSTATUS NtAllocateVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    PSIZE_T regionSize,
    ULONG allocationType,
    ULONG protect
);

#endif // SYSCALLS_H
