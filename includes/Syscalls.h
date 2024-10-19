#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include <winternl.h>  // Include for POBJECT_ATTRIBUTES and NT functions

// Define function pointers for necessary syscalls
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

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,  // Fixed declaration
    PLARGE_INTEGER MaximumSize OPTIONAL,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle OPTIONAL);

typedef NTSTATUS(NTAPI* NtCreateProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,  // Fixed declaration
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL);

// Function pointer for NtSetInformationFile
typedef NTSTATUS(WINAPI* NtSetInformationFile_t)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
    );

// Struct to hold syscall pointers
typedef struct _SyscallStruct {
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtProtectVirtualMemory_t NtProtectVirtualMemory;
    NtWriteVirtualMemory_t NtWriteVirtualMemory;
    NtQueueApcThread_t NtQueueApcThread;
    NtCreateSection_t NtCreateSection;
    NtCreateProcess_t NtCreateProcess;
    NtSetInformationFile_t NtSetInformationFile;  // Added for NtSetInformationFile
} SyscallStruct;

// Correct declaration of the function
BOOL InitializeSyscallStruct(SyscallStruct* St);

#endif
