#include "src/ApiHashing/ApiHashing.h"
#include "src/defines.h"

void init_hashing() {
    PDWORD functionAddress = NULL;

    functionAddress = getFunctionAddressByHash((char *) "ntdll", RTLGETNTVERSIONNUMBERS);
    _RtlGetNtVersionNumbers = (_RTLGETNTVERSIONNUMBERS) functionAddress;


    functionAddress = getFunctionAddressByHash((char *) "kernel32", WRITECONSOLEA);
    _WriteConsoleA = (_WRITECONSOLEA) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "kernel32", GETSTDHANDLE);
    _GetStdHandle = (_GETSTDHANDLE) functionAddress;

}

void WriteTextAndDword(const char* text, DWORD value, BOOL showNumber) {
    HANDLE hConsole = _GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return;
    }

    char buffer[128];
    int length = 0;

    const char* current = text;
    while (*current) {
        buffer[length++] = *current++;
    }


    if(showNumber) {
        buffer[length++] = ':';
        buffer[length++] = ' ';

        DWORD temp = value;
        char digits[16];
        int digitCount = 0;

        do {
            digits[digitCount++] = '0' + (temp % 10);
            temp /= 10;
        } while (temp > 0);

        for (int i = digitCount - 1; i >= 0; i--) {
            buffer[length++] = digits[i];
        }
    }


    buffer[length++] = '\n';
    buffer[length] = '\0';

    DWORD written;
    _WriteConsoleA(hConsole, buffer, length, &written, NULL);
}

int main(void) {
    init_hashing();

    DWORD majorVersion = 0, minorVersion = 0, buildNumber = 0;
    _RtlGetNtVersionNumbers(&majorVersion, &minorVersion, &buildNumber);
    buildNumber &= ~0xF0000000; //Build number high bit clear

    WriteTextAndDword("You do not have to include headers into your code :)", 0, FALSE);
    WriteTextAndDword("Major Version", majorVersion, TRUE);
    WriteTextAndDword("Minor Version", minorVersion, TRUE);
    WriteTextAndDword("Build Number", buildNumber, TRUE);


    return 0;
}
