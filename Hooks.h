#pragma once

#include <Windows.h>

#define VAR_BUFFER_SIZE 0x44
#define OCCURENCES_OFFSET 0x0
#define RANDBUFFER_OFFSET OCCURENCES_OFFSET + sizeof(DWORD)
#define INPUT_OFFSET RANDBUFFER_OFFSET + 0x20
#define INPUT2_OFFSET INPUT_OFFSET + 0x10

typedef NTSTATUS (__fastcall* tBCryptGenRandom)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	PUCHAR pbBuffer,
	ULONG cbBuffer,
	ULONG dwFlags
);

typedef BOOL (__fastcall* tQueryPerformanceCounter)(
	LARGE_INTEGER* lpPerformanceCount
);

typedef void (__fastcall* tGetSystemTimeAsFileTime)(
	LPFILETIME lpSystemTimeAsFileTime
);

typedef void* (__fastcall* tmemcpy)(
	void* dest,
	const void* src,
	size_t count
);

namespace Hooks 
{
	BOOL IATHookEx(HANDLE Process, BYTE* procBase, const char* dllName, const char* funcName, void* newFunc, void** oldFunc);
	BOOL IATUnHookEx(HANDLE Process, BYTE* procBase, const char* dllName, const char* funcName, void* oldFunc);

	NTSTATUS __fastcall GenRandomHook(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
	BOOL __fastcall QueryCounterHook(LARGE_INTEGER* lpPerformanceCount);
	//void __fastcall Time64Hook(LPFILETIME lpSystemTimeAsFileTime);

	BOOL HookAll(HANDLE hProc, DWORD procId, BYTE* procBase);
	void UnHookAll(HANDLE hProc);
	BOOL GetVars(HANDLE hProc, HANDLE hPrimaryThread, BYTE* varBuffer);
}