#pragma once

#include <Windows.h>

namespace Process
{
	void* GetModuleBase(const char* modName, DWORD procId);
	void* GetProcAddressEx(HANDLE hProc, DWORD procId, const char* modName, const char* procName);
}