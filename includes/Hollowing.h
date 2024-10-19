#ifndef HOLLOWING_H
#define HOLLOWING_H

#include <windows.h>
#include "Syscalls.h"

// Ensure 'bool' is used as the return type
bool UnhookDLL(HANDLE hProcess, SyscallStruct* St);

#endif // HOLLOWING_H
