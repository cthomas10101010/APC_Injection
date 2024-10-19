#include "ProcessCreation.h"
#include <stdio.h>
#include <windows.h>

// Function to create a suspended process
BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    Si.cb = sizeof(STARTUPINFO);

    char targetProcess[] = "calc.exe";  // mutable string
    printf("\n[i] Running: \"%s\" ... ", targetProcess);

    if (!CreateProcessA(NULL, targetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    printf("[+] Process Created Successfully (PID: %d)\n", *dwProcessId);
    return TRUE;
}

BOOL CreateDebuggedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    Si.cb = sizeof(STARTUPINFO);

    char targetProcess[] = "calc.exe";  // mutable string
    printf("\n[i] Running: \"%s\" ... ", targetProcess);

    if (!CreateProcessA(NULL, targetProcess, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    printf("[+] Process Created in Debug Mode Successfully (PID: %d)\n", *dwProcessId);
    return TRUE;
}
