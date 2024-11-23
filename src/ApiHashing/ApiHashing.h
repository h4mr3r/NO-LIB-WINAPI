#ifndef NOLIB_API_HASHING_H
#define NOLIB_API_HASHING_H

#include "src/Winblows.h"
#include "src/Utilities/string_utilities.h"

DWORD getHashFromString(char *string);
PDWORD getFunctionAddressByHash(char *library, DWORD hash);

#endif //NOLIB_API_HASHING_H
