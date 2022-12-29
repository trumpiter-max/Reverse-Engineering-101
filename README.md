# Reverse Engineering 101

## Table of content
 - [PE file](#pe-file)
    - [Introduction](#introduction)
    - [DOS Header](#dos-header)
    - [PE header](#the-pe-header)
    - [Sections table](#sections-table)
    - [CPP script](#pe-script)
 - [MessageBox](#messagebox)
    - [CPP script](/script/messagebox.cpp)
## PE File

This type of file using for Win32, used on Win32 for almost purpose 

Why we need to know PE file?
 - Injecting code into executable file
 - Manual unpacking product file (being packed)

---

### Introduction

**Basic structure of PE file:**
```
DOS MZ header
DOS stub
PE header
Section table

Section 1
Section 2
...
Section n
```

PE file includes 2 sections at least:
 - 1 section for code
 - 1 section for data

Ex: an application using for Window NT includes:
 - Executable Code Section: .text (Micro$oft)/CODE (Borland).
2. Data Sections: `.data`, `.rdata` or `.bss` (Micro$oft)/DATA (Borland)
3. Resources Section: `.rsrc`
4. Export Data Section: `.edata`
5. Import Data Section: `.idata`
6. Debug Information Section: `.debug`

Every field of PE header declare space on physical memory.

Some definitions:

 - `Virtual memory`: is a common technique used in a computer's operating system (OS), uses both hardware and software to enable a computer to compensate for physical memory shortages, temporarily transferring data from random access memory (RAM) to disk storage
 - `Invisible layer`: a layer between processor and OS
 - `Page table`: list of all Process including address of physical memory is using 
 - `PE header` has 2 alignment fields:
    - `Section alignment`: method how to arrange sections above
    - `File alignment` (`512 bytes` or `200h`): method how to arrange sections in file on disk and size of sector is optimized in `Loading process`
 - `Hmodule`: address where the beginning of file

---

### DOS Header

Accounting for `first 64 bytes` of file, defined in `window.inc` or `winnt.h`. In PE file, magic of DOS header includes value: `4Dh, 5Ah (2 bytes first)`. `Ifanview` which at the end of DOS header and beginning of DOS stub, is DWORD and includes offset of PE header

---

### The PE header

Getting header from `IMAGE_NT_HEADERS` including 3 part (defined in `windows.inc`):
 - `Signature`: value is often `50h`, `45h`, `00h`
 - `FileHeader`: next 20 bytes including information of properties
   - `NumberOfSections`
   - `Characteristics`: identify this PE file is executable or DLL
 - `OptionalHeader`: next 224 bytes including Logic map of PE file
   - `Data Directory`: an array of 16 `IMAGE_DATA_DIRECTORY` structures, ex: `import address table`
      - `VirtualAddress (VA)`
      - `import table`: get it from `IMAGE_IMPORT_DESCRIPTOR`
      - `isize`: include size of bytes by data structure 
   - `AddressOfEntryPoint (RVA)`: first instruction loaded by PE loader. Moreover, we need `VA` to read data when program in `StarForce` mode
   - `ImageBase`: load address prioritize for PE file
   - `SectionAlignment`: linker of all Sections in memory
   - `FileAlignment`: linker of all Sections in file
   - `SizeOfImage`: size of PE image in memory
   - `SizeOfHeaders`: size of all headers and section table

---

### Sections table

Get it from `IMAGE_SECTION_HEADER`

---

### PE script

Using this [simple CPP program](/script/pe.cpp) get information from PE file.

Using this program with PowerShell or cmd: `.\pe.exe <path/of/file>`, then result will be similar like this:

*Note: this script only read data of x64 PE file*

![Result 1](https://i.ibb.co/Nn3Ld8H/Screenshot-2022-12-26-201219.png)

![Result 2](https://i.ibb.co/PQPjDsz/Screenshot-2022-12-26-201937.png)

It will display all information of PE file:
 - `NT header` 
   - Pointer To EntryPoint
   - CheckSum
   - ImageBase
   - FileAlignment
   - SizeOfImage
 - `Sections`
   - Name section
   - Characteristics
   - RawSize
   - VirtualAddress
   - VirtualSize
 - `Imports table`
   - Name of Dll module & its name function

---

### MessageBox

Program (C/C++) to insert into any EXE file a MessageBox "You've got infected". After showing that MessageBox, the program continues to run normally.

You write a program to insert a code into EXE file so that when running the modified EXE file, it will turn on the MessageBox, after pressing the Ok button on that MessageBox, the file continues to run as it was.

First step, we need to add a new section named `.inflect` 





