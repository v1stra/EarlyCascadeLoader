#include <windows.h>
#include <stdio.h>
#include <psapi.h>

WINBASEAPI void *__cdecl    MSVCRT$memcpy(void * _Dst, const void * _Src, size_t _MaxCount);
WINBASEAPI size_t __cdecl   MSVCRT$strlen(const char *_Str);
WINBASEAPI int __cdecl      MSVCRT$memcmp(const void *_Buf1, const void *_Buf2, size_t _Size);
WINBASEAPI int __cdecl      MSVCRT$vsnprintf(char *  d, size_t n, const char * format, va_list arg);
WINBASEAPI LONGLONG __cdecl MSVCRT$_rotr64(ULONGLONG value, int shift);


WINBASEAPI BOOL WINAPI      PSAPI$GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);

WINBASEAPI DWORD WINAPI     KERNEL32$GetLastError (VOID);
WINBASEAPI BOOL WINAPI      KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
WINBASEAPI LPVOID WINAPI    KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI      KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI BOOL WINAPI      KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI FARPROC WINAPI   KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);


#ifndef _BOF
#define MSVCRT$memcpy memcpy
#define MSVCRT$strlen strlen
#define MSVCRT$memcmp memcmp
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$_rotr64 _rotr64

#define PSAPI$GetModuleInformation GetModuleInformation

#define KERNEL32$GetProcAddress GetProcAddress
#define KERNEL32$GetLastError GetLastError
#define KERNEL32$CreateProcessA CreateProcessA
#define KERNEL32$VirtualAllocEx VirtualAllocEx
#define KERNEL32$WriteProcessMemory WriteProcessMemory
#define KERNEL32$ResumeThread ResumeThread
#endif
