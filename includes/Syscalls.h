#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

// Define function pointers for syscalls
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(WINAPI* NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext OPTIONAL,
    PVOID ApcStatusBlock OPTIONAL,
    ULONG ApcReserved OPTIONAL);

// Struct to hold syscall pointers
typedef struct _SyscallStruct {
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtProtectVirtualMemory_t NtProtectVirtualMemory;
    NtWriteVirtualMemory_t NtWriteVirtualMemory;
    NtQueueApcThread_t NtQueueApcThread;
} SyscallStruct, * PSyscallStruct;

BOOL InitializeSyscallStruct(PSyscallStruct St);

#endif
