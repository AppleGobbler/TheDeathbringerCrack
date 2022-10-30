#include <Windows.h>
#include <iostream>
#include <intrin.h>
#include <time.h>

#include "Hooks.h"

const int powersOfTwo[9] = { 2, 4, 8, 16, 32, 64, 128, 0x1B, 0x36 };
const char hexToChar[0x10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

#define CRACKME_MOD_COUNT 6

void SupplyKey(DWORD* key)
{
	*key = 0x6a09e667;
	key[1] = 0xbb67ae85;
	key[2] = 0x3c6ef372;
	key[3] = 0xa54ff53a;
	key[4] = 0x510e527f;
	key[5] = 0x9b05688c;
	key[6] = 0x1f83d9ab;
	key[7] = 0x5be0cd19;
}

extern "C" void EncryptKey(DWORD* key, DWORD* rngBuffer, UINT64 param3, int param4);

void SwapDwordEndians(DWORD* key, int count) 
{
	for (int i = 0; i < count; i++) 
		key[i] = (key[i] >> 0x18) | ((key[i] & 0xFF0000) >> 0x8) 
		| ((key[i] & 0xFF00) << 0x8) | ((key[i] & 0xFF) << 0x18);
}

/*
void EncryptKey(DWORD* keyBuffer, DWORD* randomBuffer, UINT64 param3, int param4) // param3 == 0x40, param4 == 1
{
	__m128i auVar3 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	if (param4 == 1)
		auVar3 = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0B, 0x0A, 0x09, 0x08, 0x0F, 0x0E, 0x0D, 0x0C };

	__m128i Global1 = { 0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71, 0xCF, 0xFB, 0xC0, 0xB5, 0xA5, 0xDB, 0xB5, 0xE9 };
	__m128i Global2 = { 0x5b, 0xc2, 0x56, 0x39, 0xf1, 0x11, 0xf1, 0x59, 0xa4, 0x82, 0x3f, 0x92, 0xd5, 0x5e, 0x1c, 0xab };

	__m128i auVar23 = *(__m128i*)inputBuffer, auVar10 = *(__m128i*)&inputBuffer[4];

	__m128i var7 = _mm_shuffle_epi32(auVar23, 0xB1);
	__m128i var8 = _mm_shuffle_epi32(auVar10, 0x1B);

	__m128i auVar20 = _mm_alignr_epi8(auVar23, auVar10, 0x8);

	auVar23 = _mm_blend_epi16(auVar10, auVar23, 0xf0);

	if (0x3f < param3) 
	{
		__m128i* randomGeneration = (__m128i*)(randomBuffer + 0x8);
		param3 >>= 6;
		do 
		{
			__m128i auVar8 = _mm_shuffle_epi8(randomGeneration[-1], auVar3);
			__m128i auVar9 = _mm_shuffle_epi8(randomGeneration[0], auVar3);
			__m128i auVar14 = _mm_shuffle_epi8(randomGeneration[1], auVar3);
			__m128i auVar4 = _mm_shuffle_epi8(randomGeneration[-2], auVar3);

			__m128i var9 = _mm_add_epi32(Global1, auVar4); //
			__m128i var10 = _mm_alignr_epi8(auVar14, auVar9, 0x4);

			__m128i auVar18 = _mm_sha256rnds2_epu32(var7, auVar20, var9);
			var9 = _mm_shuffle_epi32(var9, 0xE);
			__m128i auVar21 = _mm_sha256rnds2_epu32(auVar20, auVar18, var9);
			auVar4 = _mm_sha256msg1_epu32(auVar4, auVar8);

			__m128i var11 = _mm_add_epi32(var10, auVar4);

			__m128i var12 = _mm_add_epi32(Global2, auVar8);

			__m128i auVar19 = _mm_sha256rnds2_epu32(auVar18, auVar21, auVar10);
			var9 = _mm_shuffle_epi32(var9, 0xE);
			auVar21 = _mm_sha256rnds2_epu32(auVar21, auVar19, var9);
			auVar8 = _mm_sha256msg1_epu32(auVar8, auVar9);
			auVar18 = _mm_sha256msg2_epu32(auVar18, var11);

			param3--;
		} while (param3 != 0);
	}
}*/

void GenerateLongKey(DWORD* key, DWORD size, DWORD* longKey) 
{
	__m128i Insertion = *(__m128i*)((UINT64)(key)+size - 0x10);
	__m128i keyGenAssist = { 0 };
	DWORD extraction = 0;

	if (size == 0x20)
	{
		*(__m128i*)longKey = *(__m128i*)key;
		*(__m128i*)(&longKey[4]) = *(__m128i*)(&key[4]);

		keyGenAssist = _mm_aeskeygenassist_si128(Insertion, 0);
		extraction = _mm_extract_epi32(keyGenAssist, 3);
		extraction ^= *longKey;
		extraction ^= 1;
		longKey[8] = extraction;
		extraction ^= longKey[1];
		longKey[9] = extraction;
		extraction ^= longKey[2];
		longKey[10] = extraction;
		extraction ^= longKey[3];
		longKey[11] = extraction;

		for (int i = 0; i < 6 * 8; i += 8)
		{
			Insertion = _mm_insert_epi32(Insertion, longKey[11 + i], 3);
			keyGenAssist = _mm_aeskeygenassist_si128(Insertion, 0);
			extraction = _mm_extract_epi32(keyGenAssist, 2);
			extraction ^= longKey[4 + i];
			longKey[12 + i] = extraction;
			extraction ^= longKey[5 + i];
			longKey[13 + i] = extraction;
			extraction ^= longKey[6 + i];
			longKey[14 + i] = extraction;
			extraction ^= longKey[7 + i];
			longKey[15 + i] = extraction;
			Insertion = _mm_insert_epi32(Insertion, extraction, 3);

			keyGenAssist = _mm_aeskeygenassist_si128(Insertion, 0);
			extraction = _mm_extract_epi32(keyGenAssist, 3);
			extraction ^= powersOfTwo[i / 8];
			extraction ^= longKey[8 + i];
			longKey[16 + i] = extraction;
			extraction ^= longKey[9 + i];
			longKey[17 + i] = extraction;
			extraction ^= longKey[10 + i];
			longKey[18 + i] = extraction;
			extraction ^= longKey[11 + i];
			longKey[19 + i] = extraction;
		}
	}
	else if (size == 0x10)
	{
		*(__m128i*)longKey = *(__m128i*)key;

		keyGenAssist = _mm_aeskeygenassist_si128(Insertion, 0);
		extraction = _mm_extract_epi32(keyGenAssist, 3);
		extraction ^= *longKey;
		extraction ^= 1;
		longKey[4] = extraction;
		extraction ^= longKey[1];
		longKey[5] = extraction;
		extraction ^= longKey[2];
		longKey[6] = extraction;
		extraction ^= longKey[3];
		longKey[7] = extraction;

		for (int i = 0; i < 9 * 4; i += 4)
		{
			Insertion = _mm_insert_epi32(Insertion, longKey[7 + i], 3);

			keyGenAssist = _mm_aeskeygenassist_si128(Insertion, 0);
			extraction = _mm_extract_epi32(keyGenAssist, 3);
			extraction ^= powersOfTwo[i / 4];
			extraction ^= longKey[4 + i];
			longKey[8 + i] = extraction;
			extraction ^= longKey[5 + i];
			longKey[9 + i] = extraction;
			extraction ^= longKey[6 + i];
			longKey[10 + i] = extraction;
			extraction ^= longKey[7 + i];
			longKey[11 + i] = extraction;
		}
	}
}

/*
BOOL SupplyInput(UINT64* input) 
{
	LARGE_INTEGER lInt = { 0 };
	if (!QueryPerformanceCounter(&lInt))
		return FALSE;

	input[0] += lInt.QuadPart;
	input[1] += time(NULL);

	return TRUE;
}*/

void EncryptInput(__m128i* input, const BYTE* longKey, int limit)
{
	int indexOne = 2, indexTwo = 4;
	int counter = 1;
	*(UINT64*)(input) ^= *(UINT64*)(longKey);
	*(UINT64*)((UINT64)input + 8) ^= *(UINT64*)(longKey + 8);
	do {
		indexOne = counter;
		indexTwo = counter + 1;
		indexOne += indexOne;
		indexTwo += indexTwo;
		counter += 2;
		*input = _mm_aesenc_si128(*input, *(__m128i*)(&longKey[indexOne * 8]));
		*input = _mm_aesenc_si128(*input, *(__m128i*)(&longKey[indexTwo * 8]));
	} while (counter < limit - 1);
	indexOne = counter;
	indexOne += indexOne;
	*input = _mm_aesenc_si128(*input, *(__m128i*)(&longKey[indexOne * 8]));
	indexOne = limit;
	indexOne += indexOne;
	*input = _mm_aesenclast_si128(*input, *(__m128i*)(&longKey[indexOne * 8]));
}

void StringEncryptInput(__m128i* input, const char* key) 
{
	*(UINT64*)(input) ^= *(UINT64*)(key);
	*(DWORD*)((UINT64)input + 8) ^= *(DWORD*)(key + 8);
	*(BYTE*)((UINT64)input + 12) ^= *(key + 12);
}

void PrintKey(BYTE* input) 
{
	std::cout << "Your key is: ";
	for (int i = 0; i < 13; i++) 
		std::cout << hexToChar[(input[i] & 0xF0) >> 0x4] << hexToChar[input[i] & 0xF];
	std::cout << std::endl;
}

int main() 
{
	STARTUPINFO si;
	GetStartupInfo(&si);
	si.lpTitle = _strdup("CrackMe.exe");
	if (!si.lpTitle)
		return -1;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	
	char* CrackMePath = _strdup("CrackMe.exe");
	if (!CrackMePath) 
	{
		free(si.lpTitle);
		return -1;
	}

	if (!CreateProcess(NULL, CrackMePath, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi))
	{
		free(CrackMePath);
		free(si.lpTitle);
		return -1;
	}

	free(CrackMePath);
	free(si.lpTitle);
	// Start CrackMe.exe on a suspended thread (due to DEBUG_ONLY_THIS_PROCESS)
	// Using CREATE_SUSPENDED creates a problem where winapi functions don't work due to PE and PEB structures being uninitialized
	DEBUG_EVENT debugEvent = { 0 };
	BYTE* procBase = NULL;
	int ModuleCount = 0;
	while (1)
	{
		WaitForDebugEvent(&debugEvent, INFINITE);

		if (debugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
			ModuleCount++;
		else if (debugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
			procBase = (BYTE*)debugEvent.u.CreateProcessInfo.lpBaseOfImage;

		if (ModuleCount == CRACKME_MOD_COUNT)
			break;

		ContinueDebugEvent(debugEvent.dwProcessId,
			debugEvent.dwThreadId,
			DBG_CONTINUE);
	}

	SuspendThread(pi.hThread);

	DebugSetProcessKillOnExit(FALSE);
	DebugActiveProcessStop(pi.dwProcessId);
	// Get process base address, suspend thread, and stop debugging after modules are loaded
	if (!Hooks::HookAll(pi.hProcess, pi.dwProcessId, procBase))
		return -1;

	BYTE* varBuffer = (BYTE*)malloc(VAR_BUFFER_SIZE - sizeof(DWORD));

	BYTE rngBuffer[0x40] = { 0 };
	BYTE* input = { 0 };	// size is 0x10
	BYTE* input2 = { 0 }; // size is 0x10

	if (!Hooks::GetVars(pi.hProcess, pi.hThread, varBuffer)) // Some values are based on timers and RNG. The only way for me to get them is to hook their functions
		return -1;

	memcpy(rngBuffer + 0x20, varBuffer + RANDBUFFER_OFFSET - sizeof(DWORD), 0x20);
	input = varBuffer + INPUT_OFFSET - sizeof(DWORD);
	input2 = varBuffer + INPUT2_OFFSET - sizeof(DWORD);

	BYTE key[0x20] = { 0 };

	SupplyKey((DWORD*)key);
	EncryptKey((DWORD*)key, (DWORD*)rngBuffer, 0x40, 0x1);

	*(DWORD*)rngBuffer = 0x80;
	memset(rngBuffer + 0x4, 0x0, 0x38);
	*(DWORD*)(rngBuffer + 0x3C) = 0x20000;

	EncryptKey((DWORD*)key, (DWORD*)rngBuffer, 0x40, 0x1);
	SwapDwordEndians((DWORD*)key, 0x10);
	
	BYTE longKey[0xF0] = { 0 };

	GenerateLongKey((DWORD*)key, 0x20, (DWORD*)longKey);
	EncryptInput((__m128i*)input, longKey, 0xE);

	*(UINT64*)input2 += *(UINT64*)input;
	*(UINT64*)(input2 + sizeof(UINT64)) += *(UINT64*)(input + sizeof(UINT64));

	EncryptInput((__m128i*)input2, longKey, 0xE);

	ZeroMemory(longKey, 0xF0);

	GenerateLongKey((DWORD*)input2, 0x10, (DWORD*)longKey);
	EncryptInput((__m128i*)input, longKey, 0xA);
	StringEncryptInput((__m128i*)input, "KeyfrAQBc8Wsa");

	PrintKey(input);

	free(varBuffer);
	Hooks::UnHookAll(pi.hProcess);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	system("pause");
	return 0;
}