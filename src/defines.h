#ifndef NOLIB_DEFINES_H
#define NOLIB_DEFINES_H

#include "src/Winblows.h"


#pragma region APIHASHING
#pragma region NTDLL

#define RTLGETNTVERSIONNUMBERS 0xb406c4df
typedef DWORD(WINAPI *_RTLGETNTVERSIONNUMBERS)(DWORD*, DWORD*, DWORD*);
extern SEC_DATA _RTLGETNTVERSIONNUMBERS _RtlGetNtVersionNumbers;

#pragma endregion

#pragma region KERNEL32

#define WRITECONSOLEA 0x3226738c
#define GETSTDHANDLE 0xe3b9876a

typedef BOOL (WINAPI *_WRITECONSOLEA)(HANDLE hConsoleOutput, const void *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCHarsWritten, LPVOID lpReserved);
typedef HANDLE (WINAPI *_GETSTDHANDLE)(DWORD nStdHandle);

extern SEC_DATA _WRITECONSOLEA _WriteConsoleA;
extern SEC_DATA _GETSTDHANDLE _GetStdHandle;

#pragma endregion

#pragma endregion


#endif //NOLIB_DEFINES_H
