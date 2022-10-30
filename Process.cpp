#include "Process.h"

#include <TlHelp32.h>

void* Process::GetModuleBase(const char* modName, DWORD procId)
{
	MODULEENTRY32 modEntry = { 0 };
	modEntry.dwSize = sizeof(modEntry);

	HANDLE hSnap = 0;
	do
	{
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);
	} while (GetLastError() == ERROR_BAD_LENGTH);

	if (!hSnap)
		return NULL;

	if (hSnap == INVALID_HANDLE_VALUE || !Module32First(hSnap, &modEntry))
		goto Exit;

	do
	{
		if (!strcmp(modName, modEntry.szModule))
		{
			CloseHandle(hSnap);
			return modEntry.hModule;
		}
	} while (Module32Next(hSnap, &modEntry));

Exit:
	CloseHandle(hSnap);
	return NULL;
}

void* Process::GetProcAddressEx(HANDLE hProc, DWORD procId, const char* modName, const char* procName)
{
	BYTE* modBase = (BYTE*)GetModuleBase(modName, procId);
	if (!modBase)
		return NULL;

	BYTE* base = (BYTE*)malloc(0x1000);
	if (!base)
		return NULL;

	if (!ReadProcessMemory(hProc, modBase, base, 0x1000, NULL))
		return NULL;

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)(base))->e_lfanew);
	IMAGE_OPTIONAL_HEADER* optHeader = &ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY* exportEntry = &optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!exportEntry->Size)
	{
		free(base);
		return NULL;
	}

	BYTE* exportData = (BYTE*)malloc(exportEntry->Size);
	if (!exportData)
	{
		free(base);
		return NULL;
	}

	if (!ReadProcessMemory(hProc, modBase + exportEntry->VirtualAddress, exportData, exportEntry->Size, NULL))
	{
		free(base);
		free(exportData);
		return NULL;
	}

	BYTE* localBase = exportData - exportEntry->VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)exportData;

	if (((UINT_PTR)(procName) & 0xFFFFFF) <= MAXWORD)
	{
		DWORD* EAT = (DWORD*)(localBase + exportDir->AddressOfFunctions);
		WORD Base = LOWORD(exportDir->Base - 1);
		WORD ordinal = LOWORD(procName) - Base;
		DWORD FuncRVA = EAT[ordinal];

		free(exportData);
		free(base);

		if (FuncRVA >= exportEntry->VirtualAddress && FuncRVA < exportEntry->VirtualAddress + exportEntry->Size)
		{
			char* fullExport = (char*)(localBase + FuncRVA);
			if (!strlen(fullExport))
				return NULL;

			char* dllName = fullExport;
			char* functionName = strchr(dllName, '.');

			*functionName = '\0';
			if (*(functionName++) == '#')
				functionName = (char*)(LOWORD(atoi(++functionName)));

			return GetProcAddressEx(hProc, procId, dllName, functionName);
		}

		return modBase + FuncRVA;
	}

	DWORD max = exportDir->NumberOfNames - 1;
	DWORD min = 0;
	DWORD FuncRVA = 0;

	while (min <= max)
	{
		int mid = (min + max) / 2;

		DWORD currNameRVA = ((DWORD*)(localBase + exportDir->AddressOfNames))[mid];
		char* currName = (char*)(localBase + currNameRVA);

		int res = strcmp(currName, procName);
		if (res < 0)
			min = mid + 1;
		else if (res > 0)
			max = mid - 1;
		else
		{
			int ordinal = ((WORD*)(localBase + exportDir->AddressOfNameOrdinals))[mid];
			FuncRVA = ((DWORD*)(localBase + exportDir->AddressOfFunctions))[ordinal];
			break;
		}
	}

	free(exportData);
	free(base);

	if (!FuncRVA)
		return NULL;

	if (FuncRVA >= exportEntry->VirtualAddress && FuncRVA < exportEntry->VirtualAddress + exportEntry->Size)
	{
		char* fullExport = (char*)(localBase + FuncRVA);
		if (!strlen(fullExport))
			return NULL;

		char* dllName = fullExport;
		char* functionName = strchr(dllName, '.');

		*functionName = '\0';
		if (*(functionName++) == '#')
			functionName = (char*)(LOWORD(atoi(++functionName)));

		return GetProcAddressEx(hProc, procId, dllName, functionName);
	}

	return modBase + FuncRVA;
}
