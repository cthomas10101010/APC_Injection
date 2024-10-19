// Hollowing.h
#ifndef HOLLOWING_H
#define HOLLOWING_H

#include <windows.h>
#include "Syscalls.h"

// Declare HollowProcess function
BOOL HollowProcess(HANDLE hProcess, unsigned char* payload, SIZE_T payloadSize, SyscallStruct* St);

// Declare UnhookDLL function
BOOL UnhookDLL(HANDLE hProcess, SyscallStruct* St);

#endif // HOLLOWING_H
