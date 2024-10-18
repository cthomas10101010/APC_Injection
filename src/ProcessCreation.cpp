#include "ProcessCreation.h"
#include <stdio.h>
#include <tchar.h>

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];
    STARTUPINFO Si = {0};
    PROCESS_INFORMATION Pi = {0};

    Si.cb = sizeof(STARTUPINFO);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n\t[i] Running: \"%s\" ... ", lpPath);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return TRUE;
}

BOOL CreateDebuggedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];
    STARTUPINFO Si = {0};
    PROCESS_INFORMATION Pi = {0};

    Si.cb = sizeof(STARTUPINFO);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n\t[i] Running: \"%s\" ... ", lpPath);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return TRUE;
}
