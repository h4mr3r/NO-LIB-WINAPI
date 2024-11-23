## The Core Idea: Leveraging kernel32.dll

Every Windows application inherently loads kernel32.dll during execution. This DLL provides access to essential Windows API functions, including LoadLibraryA, which is commonly used to load other DLLs dynamically. The typical approach involves including Windows API headers and calling LoadLibraryA or related functions directly. But here's the interesting part: since kernel32.dll is already loaded, why not skip including bulky header files and use those API functions directly?

It can be done with simple
```C
extern void* LoadLibraryA(const char* dllName);
```

## Approach
By avoiding the inclusion of standard libraries, you can leverage the following techniques:

1. Use extern to Declare API Functions
2. Implement API Hashing
3. Implement you own custom minimal windows header.
4. Add selected winapi functions that suites your needs

Generally this approach can improve stealth because there are no static imports and binary size would be much smaller.

Have fun :)