# *Windows* Tiny PE

[![Windows](badges/Microsoft-Windows.svg)](https://www.microsoft.com/en-ie/windows)
![License](badges/License-MIT.svg)

## Introduction

A manually created tiny **Windows x86 PE** file that can run on *Windows XP* and pop up a message box. It is only **208** bytes.

```
4D 5A 50 50 50 50 FF 15 B0 00 40 00 50 45 00 00
4C 01 01 00 AA AA AA AA AA AA AA AA AA AA AA AA
70 00 0F 01 0B 01 01 00 4D 65 73 73 61 67 65 42
6F 78 41 00 02 00 00 00 AA AA AA AA 0C 00 00 00
00 00 40 00 04 00 00 00 04 00 00 00 AA AA AA AA
AA AA AA AA 04 00 AA AA 00 00 00 00 D0 00 00 00
BC 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02 00 00 00 75 73 65 72 33 32 00 00 BC 00 00 00
00 00 00 00 BB BB BB BB BB BB BB BB D0 00 00 00
00 00 00 00 D0 00 00 00 00 00 00 00 00 00 00 00
26 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 84 00 00 00 B0 00 00 00
```

## Detailed Design

### MS-DOS Header

The `IMAGE_DOS_HEADER` structure is located from `0x00` to `0x3F`.

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
  } IMAGE_DOS_HEADER;
```

```
4D 5A 50 50 50 50 FF 15 B0 00 40 00 50 45 00 00
4C 01 01 00 AA AA AA AA AA AA AA AA AA AA AA AA
70 00 0F 01 0B 01 01 00 4D 65 73 73 61 67 65 42
6F 78 41 00 02 00 00 00 AA AA AA AA 0C 00 00 00
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

`e_lfanew` (`0x3C`) is `0x0000000C`. It is an offset where *PE Header* is placed.

### PE Header

*PE Header* is an `IMAGE_NT_HEADERS` structure consisting of a PE signature, an `IMAGE_FILE_HEADER` structure and an `IMAGE_OPTIONAL_HEADER` structure.

```c
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;
```

#### Signature

The PE signature `"PE\0\0"` is at `0x0C`.

```
.. .. .. .. .. .. .. .. .. .. .. .. 50 45 00 00
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

#### COFF File Header

The `IMAGE_FILE_HEADER` structure is located from `0x10` to `0x23`.

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER;
```

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
4C 01 01 00 AA AA AA AA AA AA AA AA AA AA AA AA
70 00 0F 01 .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

- `NumberOfSections` (`0x12`) is `0x0001`, meaning there is only one section.
- `SizeOfOptionalHeader` (`0x20`) is `0x0070`. It is the size of the following `IMAGE_OPTIONAL_HEADER` structure.

#### Optional Header

The `IMAGE_OPTIONAL_HEADER` structure is located from `0x24` to `0x93`.

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;
```

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. 0B 01 01 00 4D 65 73 73 61 67 65 42
6F 78 41 00 02 00 00 00 AA AA AA AA 0C 00 00 00
00 00 40 00 04 00 00 00 04 00 00 00 AA AA AA AA
AA AA AA AA 04 00 AA AA 00 00 00 00 D0 00 00 00
BC 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02 00 00 00 75 73 65 72 33 32 00 00 BC 00 00 00
00 00 00 00 .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

- `ImageBase` (`0x40`) is `0x00400000`. It is a memory address where the file should be loaded at.
- `AddressOfEntryPoint` (`0x34`) is `0x00000002`. It is the beginning offset of executable code.
- `NumberOfRvaAndSizes` (`0x80`) is `0x00000002`, meaning there are two `IMAGE_DATA_DIRECTORY` structures. But in fact, only the data directory of *Import Table* is effective.

### Import Table

#### Data Directory

The `IMAGE_DATA_DIRECTORY` structure of *Import Table* is located from `0x8C` to `0x93`.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY;
```

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. BC 00 00 00
00 00 00 00 .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

`VirtualAddress` (`0x8C`) is `0x000000BC`. It is the offset of an array of `IMAGE_IMPORT_DESCRIPTOR` structures. Each `IMAGE_IMPORT_DESCRIPTOR` stores information about an import library. The array is terminated by an empty structure.

#### Import Descriptor

There is only one `IMAGE_IMPORT_DESCRIPTOR` structure at `0xBC`.

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
```

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. 00 00 00 00
00 00 00 00 00 00 00 00 84 00 00 00 B0 00 00 00
```

- `Name` (`0xC8`) is `0x00000084`. It is the offset of the library name.
- `FirstThunk` (`0xCC`) is `0x000000B0`. It is the offset of an array of `IMAGE_THUNK_DATA` structures. Each `IMAGE_THUNK_DATA` stores information about an import function. The array is terminated by an empty structure.

At `0x84`, we can find the library name: `user32`.

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. 75 73 65 72 33 32 00 .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

At `0xB0`, there is only one `IMAGE_THUNK_DATA` structure.

```c
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32;
```

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
26 00 00 00 .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

This function is imported by its name, corresponding to an `IMAGE_IMPORT_BY_NAME` structure at `0x26`.

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD   Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME;
```

```
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. 01 00 4D 65 73 73 61 67 65 42
6F 78 41 00 .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

Its name is `MessageBoxA`.

### Code

According to `AddressOfEntryPoint` of `IMAGE_OPTIONAL_HEADER`, the executable code starts at `0x02` and ends at `0x0B`.

```
.. .. 50 50 50 50 FF 15 B0 00 40 00 .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```

The assembly instructions are:

```asm
push    eax
push    eax
push    eax
push    eax
call    MessageBoxA
```

The destination of `call` is `0x004000B0`, which is the image base (`0x00400000`) plus the offset (`0xB0`) of `IMAGE_THUNK_DATA` for `MessageBoxA`. Its original data `0x00000026` will be replaced with the actual function address after the load is completed.

## License

Distributed under the *MIT License*. See `LICENSE` for more information.