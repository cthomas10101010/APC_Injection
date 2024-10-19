#pragma once
#ifndef IAT_HIDING_H
#define IAT_HIDING_H

#include <windows.h>

// Function declaration
FARPROC GetProcAddressReplacement(HMODULE hModule, LPCSTR lpApiName);

#endif // IAT_HIDING_H
