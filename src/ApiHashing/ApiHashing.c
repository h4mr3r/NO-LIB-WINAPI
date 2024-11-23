#include "ApiHashing.h"

extern void* LoadLibraryA(const char* dllName);

DWORD getHashFromString(char *string) {
    size_t len = strlen(string);
    DWORD hash = 0x811c9dc5;  // FNV-1a 32-bit hash initial value

    for (size_t i = 0; i < len; i++) {
        hash ^= (unsigned char)string[i];
        hash *= 0x01000193;  // FNV-1a 32-bit prime
    }

    return hash;
}

PDWORD getFunctionAddressByHash(char *library, DWORD hash) {
    HMODULE libraryBase = LoadLibraryA(library);
    if (!libraryBase) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!exportDirectoryRVA) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);
    PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD  addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        char *functionName = (char *)((DWORD_PTR)libraryBase + functionNameRVA);

        DWORD functionNameHash = getHashFromString(functionName);

        if (functionNameHash == hash) {
            DWORD functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            PDWORD functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            return functionAddress;
        }
    }

    return NULL; // Return NULL if the function hash is not found
}

