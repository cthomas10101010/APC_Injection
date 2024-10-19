#ifndef PROCESSCREATION_H
#define PROCESSCREATION_H

#include <windows.h>

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);
BOOL CreateDebuggedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);

#endif
