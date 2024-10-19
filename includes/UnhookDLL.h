#ifndef UNHOOKDLL_H
#define UNHOOKDLL_H

#include <windows.h>
#include "Syscalls.h"

// Function prototype for UnhookDLL
bool UnhookDLL(HANDLE hProcess, SyscallStruct* St);  // Ensure this is 'bool'

#endif // UNHOOKDLL_H
