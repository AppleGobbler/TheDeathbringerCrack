#include "Hooks.h"

#include "Process.h"

#include <stdio.h>

tBCryptGenRandom genRandom = NULL;
tQueryPerformanceCounter queryCounter = NULL;
tGetSystemTimeAsFileTime time64 = NULL;

BYTE* procBase = NULL;
void* funcAlloc = NULL;

#define GENRANDOMHOOK_SIZE 0x50
#define QUERYCOUNTERHOOK_SIZE 0x60
#define TIME64HOOK_SIZE 0xAC

#define VAR_BUFFER_OFFSET GENRANDOMHOOK_SIZE + QUERYCOUNTERHOOK_SIZE + TIME64HOOK_SIZE

#define GENRANDOMHOOK_OFUNC_OFFSET 0xC
#define GENRANDOMHOOK_MEMCPY_OFFSET 0x23
#define GENRANDOMHOOK_INPUT_OFFSET 0x30

#define QUERYCOUNTERHOOK_OFUNC_OFFSET 0x8
#define QUERYCOUNTERHOOK_OCCURENCES_OFFSET 0x17
#define QUERYCOUNTERHOOK_INPUT_OFFSET 0x2B
#define QUERYCOUNTERHOOK_INPUT2_OFFSET 0x3F

#define TIME64HOOK_OFUNC_OFFSET 0x7
#define TIME64HOOK_OCCURENCES_OFFSET 0x6D
#define TIME64HOOK_INPUT_OFFSET 0x7E
#define TIME64HOOK_INPUT2_OFFSET 0x92

#define MIN_MODULE_LEN 0x5

BOOL Hooks::IATHookEx(HANDLE hProc, BYTE* procBase, const char* dllName, const char* funcName, void* newFunc, void** oldFunc)
{
	BYTE* base = (BYTE*)malloc(0x1000);
	if (!base)
		return NULL;

	if (!ReadProcessMemory(hProc, procBase, base, 0x1000, NULL))
		return NULL;

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)(base))->e_lfanew);
	IMAGE_OPTIONAL_HEADER* optHeader = &ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY* importEntry = &optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importEntry->Size)
	{
		free(base);
		return NULL;
	}

	PIMAGE_IMPORT_DESCRIPTOR importData = (PIMAGE_IMPORT_DESCRIPTOR)malloc(importEntry->Size);
	if (!importData)
	{
		free(base);
		return NULL;
	}

	if (!ReadProcessMemory(hProc, procBase + importEntry->VirtualAddress, importData, importEntry->Size, NULL))
	{
		free(base);
		free(importData);
		return NULL;
	}

	BYTE* localBase = (BYTE*)importData - importEntry->VirtualAddress;
	char* modNameBuffer = (char*)malloc(MAX_PATH);
	if (!modNameBuffer) 
	{
		free(importData);
		free(base);
		return FALSE;
	}

	char* funcNameBuffer = (char*)malloc(MAX_PATH);
	if (!funcNameBuffer)
	{
		free(modNameBuffer);
		free(importData);
		free(base);
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR importOrig = importData;

	for (; importData->Characteristics != NULL; importData++)
	{
		if (!ReadProcessMemory(hProc, (const char*)(procBase + importData->Name), modNameBuffer, MIN_MODULE_LEN, NULL)) // Smallest possible dll name: "a.dll"
			continue;

		int i = MIN_MODULE_LEN - 1;
		do
		{
			if (modNameBuffer[i] == 0) // find the null terminator
				break;
			i++;
			ReadProcessMemory(hProc, (const char*)(procBase + importData->Name + i), modNameBuffer + i, 0x1, NULL);
		} while (i < MAX_PATH - 1);

		if (!strcmp(modNameBuffer, dllName))
		{
			PIMAGE_THUNK_DATA namesTablePtr = reinterpret_cast<PIMAGE_THUNK_DATA>(importData->OriginalFirstThunk + procBase);
			PIMAGE_THUNK_DATA functionTablePtr = reinterpret_cast<PIMAGE_THUNK_DATA>(importData->FirstThunk + procBase);

			IMAGE_THUNK_DATA namesTable = { 0 };
			IMAGE_THUNK_DATA functionTable = { 0 };

			do
			{
				ReadProcessMemory(hProc, namesTablePtr, &namesTable, sizeof(IMAGE_THUNK_DATA), NULL);
				ReadProcessMemory(hProc, functionTablePtr, &functionTable, sizeof(IMAGE_THUNK_DATA), NULL); 

				BYTE* funcNameLocation = (BYTE*)(namesTable.u1.AddressOfData + procBase + sizeof(WORD));

				for (int j = 0; j < MAX_PATH; j++)
				{
					ReadProcessMemory(hProc, (LPCVOID)(funcNameLocation + j), funcNameBuffer + j, 0x1, NULL);
					if (funcNameBuffer[j] == 0)
						break;
				}

				if (!strcmp(funcNameBuffer, funcName)) 
				{
					DWORD dwOld = 0;
					VirtualProtectEx(hProc, (LPVOID)((uintptr_t)functionTablePtr), sizeof(functionTablePtr), PAGE_READWRITE, &dwOld);
					*oldFunc = (void*)(uintptr_t)(functionTable.u1.Function);
					if (!WriteProcessMemory(hProc, (LPVOID)(functionTablePtr), &newFunc, sizeof(void*), NULL))
						goto Exit;
					VirtualProtectEx(hProc, (LPVOID)((uintptr_t)functionTablePtr), sizeof(functionTablePtr), dwOld, &dwOld);

					free(funcNameBuffer);
					free(modNameBuffer);
					free(importOrig);
					free(base);
					return TRUE;
				}

				namesTablePtr++;
				functionTablePtr++;
			} while (functionTable.u1.AddressOfData != NULL);
		}
	}

Exit:

	free(funcNameBuffer);
	free(modNameBuffer);
	free(importOrig);
	free(base);

	return FALSE;
}

BOOL Hooks::IATUnHookEx(HANDLE hProc, BYTE* procBase, const char* dllName, const char* funcName, void* oldFunc)
{
	BYTE* base = (BYTE*)malloc(0x1000);
	if (!base)
		return NULL;

	if (!ReadProcessMemory(hProc, procBase, base, 0x1000, NULL))
		return NULL;

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)(base))->e_lfanew);
	IMAGE_OPTIONAL_HEADER* optHeader = &ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY* importEntry = &optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importEntry->Size)
	{
		free(base);
		return NULL;
	}

	PIMAGE_IMPORT_DESCRIPTOR importData = (PIMAGE_IMPORT_DESCRIPTOR)malloc(importEntry->Size);
	if (!importData)
	{
		free(base);
		return NULL;
	}

	if (!ReadProcessMemory(hProc, procBase + importEntry->VirtualAddress, importData, importEntry->Size, NULL))
	{
		free(base);
		free(importData);
		return NULL;
	}

	BYTE* localBase = (BYTE*)importData - importEntry->VirtualAddress;
	char* modNameBuffer = (char*)malloc(MAX_PATH);
	if (!modNameBuffer)
	{
		free(importData);
		free(base);
		return FALSE;
	}

	char* funcNameBuffer = (char*)malloc(MAX_PATH);
	if (!funcNameBuffer)
	{
		free(modNameBuffer);
		free(importData);
		free(base);
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR importOrig = importData;

	for (; importData->Characteristics != NULL; importData++)
	{
		if (!ReadProcessMemory(hProc, (const char*)(procBase + importData->Name), modNameBuffer, MIN_MODULE_LEN, NULL)) // Smallest possible dll name: "a.dll"
			continue;

		int i = MIN_MODULE_LEN - 1;
		do
		{
			if (modNameBuffer[i] == 0) // find the null terminator
				break;
			i++;
			ReadProcessMemory(hProc, (const char*)(procBase + importData->Name + i), modNameBuffer + i, 0x1, NULL);
		} while (i < MAX_PATH - 1);

		if (!strcmp(modNameBuffer, dllName))
		{
			PIMAGE_THUNK_DATA namesTablePtr = reinterpret_cast<PIMAGE_THUNK_DATA>(importData->OriginalFirstThunk + procBase);
			PIMAGE_THUNK_DATA functionTablePtr = reinterpret_cast<PIMAGE_THUNK_DATA>(importData->FirstThunk + procBase);

			IMAGE_THUNK_DATA namesTable = { 0 };
			IMAGE_THUNK_DATA functionTable = { 0 };

			do
			{
				ReadProcessMemory(hProc, namesTablePtr, &namesTable, sizeof(IMAGE_THUNK_DATA), NULL);
				ReadProcessMemory(hProc, functionTablePtr, &functionTable, sizeof(IMAGE_THUNK_DATA), NULL);

				BYTE* funcNameLocation = (BYTE*)(namesTable.u1.AddressOfData + procBase + sizeof(WORD));

				for (int j = 0; j < MAX_PATH; j++)
				{
					ReadProcessMemory(hProc, (LPCVOID)(funcNameLocation + j), funcNameBuffer + j, 0x1, NULL);
					if (funcNameBuffer[j] == 0)
						break;
				}

				if (!strcmp(funcNameBuffer, funcName))
				{
					DWORD dwOld = 0;
					VirtualProtectEx(hProc, (LPVOID)((uintptr_t)functionTablePtr), sizeof(functionTablePtr), PAGE_READWRITE, &dwOld);
					if (!WriteProcessMemory(hProc, (LPVOID)(functionTablePtr), &oldFunc, sizeof(void*), NULL))
						goto Exit;
					VirtualProtectEx(hProc, (LPVOID)((uintptr_t)functionTablePtr), sizeof(functionTablePtr), dwOld, &dwOld);

					free(funcNameBuffer);
					free(modNameBuffer);
					free(importOrig);
					free(base);
					return TRUE;
				}

				namesTablePtr++;
				functionTablePtr++;
			} while (functionTable.u1.AddressOfData != NULL);
		}
	}

Exit:

	free(funcNameBuffer);
	free(modNameBuffer);
	free(importOrig);
	free(base);

	return FALSE;
}

NTSTATUS __fastcall Hooks::GenRandomHook(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags)
{
	NTSTATUS status = tBCryptGenRandom(0xABABABABABABABAB)(hAlgorithm, pbBuffer, cbBuffer, dwFlags);
	tmemcpy(0xCDCDCDCDCDCDCDCD)((void*)0xDEADBEEFDEADBEEF, pbBuffer, 0x20);
	return status;
}

BOOL __fastcall Hooks::QueryCounterHook(LARGE_INTEGER* lpPerformanceCount)
{
	BOOL ret = tQueryPerformanceCounter(0xABABABABABABABAB)(lpPerformanceCount);
	DWORD* occurences = (DWORD*)0xBEEFBEEFBEEFBEEF;
	if (*occurences == 0)
		*(UINT64*)(0xDEADBEEFDEADBEEF) = lpPerformanceCount->QuadPart;
	else
		*(UINT64*)(0xBEEFDEADBEEFDEAD) = lpPerformanceCount->QuadPart;
	(*occurences)++;
	return ret;
}

extern "C" void __fastcall Time64Hook(LPFILETIME lpSystemTimeAsFileTime);

BOOL Hooks::HookAll(HANDLE hProc, DWORD procId, BYTE* processBase)
{
	procBase = processBase;

	tmemcpy memcpyPtr = (tmemcpy)Process::GetProcAddressEx(hProc, procId, "ntdll.dll", "memcpy");

	if (!memcpyPtr)
	{
		CloseHandle(hProc);
		return FALSE;
	}

	DWORD oldRandProt = 0, oldQueryProt = 0, oldTimeProt = 0;
	if (!VirtualProtect((LPVOID)GenRandomHook, GENRANDOMHOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldRandProt))
	{
		CloseHandle(hProc);
		return FALSE;
	}

	if (!VirtualProtect((LPVOID)QueryCounterHook, QUERYCOUNTERHOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldQueryProt))
	{
		VirtualProtect((LPVOID)GenRandomHook, GENRANDOMHOOK_SIZE, oldRandProt, &oldRandProt);
		CloseHandle(hProc);
		return FALSE;
	}

	if (!VirtualProtect((LPVOID)Time64Hook, TIME64HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldTimeProt))
	{
		VirtualProtect((LPVOID)GenRandomHook, GENRANDOMHOOK_SIZE, oldRandProt, &oldRandProt);
		VirtualProtect((LPVOID)QueryCounterHook, QUERYCOUNTERHOOK_SIZE, oldQueryProt, &oldQueryProt);
		CloseHandle(hProc);
		return FALSE;
	}

	BYTE* funcBuffer = (BYTE*)malloc(GENRANDOMHOOK_SIZE + QUERYCOUNTERHOOK_SIZE + TIME64HOOK_SIZE + VAR_BUFFER_SIZE);
	BYTE* randHookBuffer = funcBuffer;
	BYTE* counterHookBuffer = randHookBuffer + GENRANDOMHOOK_SIZE;
	BYTE* timeHookBuffer = counterHookBuffer + QUERYCOUNTERHOOK_SIZE;
	DWORD* varBuffer = (DWORD*)(timeHookBuffer + TIME64HOOK_SIZE);
	if (!randHookBuffer)
	{
		free(funcBuffer);
		VirtualProtect((LPVOID)GenRandomHook, GENRANDOMHOOK_SIZE, oldRandProt, &oldRandProt);
		VirtualProtect((LPVOID)QueryCounterHook, QUERYCOUNTERHOOK_SIZE, oldQueryProt, &oldQueryProt);
		VirtualProtect((LPVOID)Time64Hook, TIME64HOOK_SIZE, oldQueryProt, &oldQueryProt);
		CloseHandle(hProc);
		return FALSE;
	}

	memcpy(randHookBuffer, GenRandomHook, GENRANDOMHOOK_SIZE);
	memcpy(counterHookBuffer, QueryCounterHook, QUERYCOUNTERHOOK_SIZE);
	memcpy(timeHookBuffer, Time64Hook, TIME64HOOK_SIZE);
	memset(varBuffer, 0x0, VAR_BUFFER_SIZE);
	
	VirtualProtect((LPVOID)GenRandomHook, GENRANDOMHOOK_SIZE, oldRandProt, &oldRandProt);
	VirtualProtect((LPVOID)QueryCounterHook, QUERYCOUNTERHOOK_SIZE, oldQueryProt, &oldQueryProt);
	VirtualProtect((LPVOID)Time64Hook, TIME64HOOK_SIZE, oldTimeProt, &oldTimeProt);

	funcAlloc = (void*)VirtualAllocEx(hProc, NULL, GENRANDOMHOOK_SIZE + QUERYCOUNTERHOOK_SIZE + TIME64HOOK_SIZE + VAR_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!funcAlloc)
	{
		free(funcBuffer);
		CloseHandle(hProc);
		return FALSE;
	}

	tBCryptGenRandom allocGenRandom = (tBCryptGenRandom)funcAlloc;
	tQueryPerformanceCounter allocQueryCounter = (tQueryPerformanceCounter)((uintptr_t)allocGenRandom + GENRANDOMHOOK_SIZE);
	tGetSystemTimeAsFileTime allocTime64 = (tGetSystemTimeAsFileTime)((uintptr_t)allocQueryCounter + QUERYCOUNTERHOOK_SIZE);
	DWORD* allocVarBuffer = (DWORD*)((uintptr_t)allocTime64 + TIME64HOOK_SIZE);

	if (!IATHookEx(hProc, procBase, "bcrypt.dll", "BCryptGenRandom", allocGenRandom, (void**)&genRandom)
		|| !IATHookEx(hProc, procBase, "KERNEL32.dll", "QueryPerformanceCounter", allocQueryCounter, (void**)&queryCounter)
		|| !IATHookEx(hProc, procBase, "KERNEL32.dll", "GetSystemTimeAsFileTime", allocTime64, (void**)&time64))
	{
		VirtualFreeEx(hProc, funcAlloc, NULL, MEM_RELEASE);
		free(funcBuffer);
		CloseHandle(hProc);
		return FALSE;
	}

	*(UINT64*)((uintptr_t)randHookBuffer + GENRANDOMHOOK_OFUNC_OFFSET) = (UINT64)genRandom;
	*(UINT64*)((uintptr_t)randHookBuffer + GENRANDOMHOOK_MEMCPY_OFFSET) = (UINT64)memcpyPtr;
	*(UINT64*)((uintptr_t)randHookBuffer + GENRANDOMHOOK_INPUT_OFFSET) = (UINT64)((uintptr_t)allocVarBuffer + RANDBUFFER_OFFSET);
	
	*(UINT64*)((uintptr_t)counterHookBuffer + QUERYCOUNTERHOOK_OFUNC_OFFSET) = (UINT64)queryCounter;
	*(UINT64*)((uintptr_t)counterHookBuffer + QUERYCOUNTERHOOK_OCCURENCES_OFFSET) = (UINT64)allocVarBuffer;
	*(UINT64*)((uintptr_t)counterHookBuffer + QUERYCOUNTERHOOK_INPUT_OFFSET) = (UINT64)((uintptr_t)allocVarBuffer + INPUT_OFFSET);
	*(UINT64*)((uintptr_t)counterHookBuffer + QUERYCOUNTERHOOK_INPUT2_OFFSET) = (UINT64)((uintptr_t)allocVarBuffer + INPUT2_OFFSET);
	
	*(UINT64*)((uintptr_t)timeHookBuffer + TIME64HOOK_OFUNC_OFFSET) = (UINT64)time64;
	*(UINT64*)((uintptr_t)timeHookBuffer + TIME64HOOK_OCCURENCES_OFFSET) = (UINT64)allocVarBuffer;
	*(UINT64*)((uintptr_t)timeHookBuffer + TIME64HOOK_INPUT_OFFSET) = (UINT64)((uintptr_t)allocVarBuffer + INPUT_OFFSET + 0x8);
	*(UINT64*)((uintptr_t)timeHookBuffer + TIME64HOOK_INPUT2_OFFSET) = (UINT64)((uintptr_t)allocVarBuffer + INPUT2_OFFSET + 0x8);

	if (!WriteProcessMemory(hProc, allocGenRandom, randHookBuffer, GENRANDOMHOOK_SIZE + QUERYCOUNTERHOOK_SIZE + TIME64HOOK_SIZE + VAR_BUFFER_SIZE, NULL))
	{
		VirtualFreeEx(hProc, funcAlloc, NULL, MEM_RELEASE);
		free(funcBuffer);
		CloseHandle(hProc);
		return FALSE;
	}

	free(funcBuffer);

	return TRUE;
}

void Hooks::UnHookAll(HANDLE hProc)
{
	IATUnHookEx(hProc, procBase, "bcrypt.dll", "BCryptGenRandom", genRandom);
	IATUnHookEx(hProc, procBase, "KERNEL32.dll", "QueryPerformanceCounter", queryCounter);
	IATUnHookEx(hProc, procBase, "KERNEL32.dll", "GetSystemTimeAsFileTime", time64);

	VirtualFreeEx(hProc, funcAlloc, NULL, MEM_RELEASE);
}

BOOL Hooks::GetVars(HANDLE hProc, HANDLE hPrimaryThread, BYTE* varBuffer)
{
	if (ResumeThread(hPrimaryThread) == -1)
	{
		free(varBuffer);
		return FALSE;
	}

	DWORD occurences = 0;
	BYTE* varBufferPtr = (BYTE*)funcAlloc + VAR_BUFFER_OFFSET;
	do
	{
		ReadProcessMemory(hProc, (LPCVOID)(varBufferPtr + OCCURENCES_OFFSET), &occurences, sizeof(DWORD), NULL);
		Sleep(100);
	} while (occurences != 4);

	ReadProcessMemory(hProc, varBufferPtr + sizeof(DWORD), varBuffer, VAR_BUFFER_SIZE - sizeof(DWORD), NULL);

	return TRUE;
}
