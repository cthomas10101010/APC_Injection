#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "IATHiding.h"

// Custom function to replace GetProcAddress (for IAT obfuscation)
FARPROC GetProcAddressReplacement(HMODULE hModule, LPCSTR lpApiName) {
    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;

    // Check DOS signature
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

    // Check NT signature
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Get Export Directory
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Retrieve function names, addresses, and ordinals
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Loop through exported functions and find the requested API
    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        LPCSTR pFuncName = (LPCSTR)(pBase + FunctionNameArray[i]);
        if (strcmp(pFuncName, lpApiName) == 0) {
            WORD ordinal = FunctionOrdinalArray[i];
            DWORD funcRVA = FunctionAddressArray[ordinal];
            return (FARPROC)(pBase + funcRVA);
        }
    }
    return NULL;
}
