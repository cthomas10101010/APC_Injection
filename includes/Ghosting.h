#ifndef GHOSTING_H
#define GHOSTING_H

#include <windows.h>
#include "Syscalls.h"

// Function to ghost a process by creating a fake executable and mapping it as a section
bool ProcessGhosting(const char* realExe, const char* fakeExe, SyscallStruct* St, HANDLE* hProcess, HANDLE* hThread);

#endif
