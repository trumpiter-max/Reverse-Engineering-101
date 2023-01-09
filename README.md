# Reverse Engineering 101

*Note: some scripts in this file being built with Visual Studio (need C++ 17 or higher). Otherwise, compiling with others like GCC (from [MinGW](https://sourceforge.net/projects/mingw/) or others) is possible*

---

# Table of content
   - [PE file](#pe-file)
      - [Introduction](#introduction)
      - [DOS Header](#dos-header)
      - [PE header](#the-pe-header)
      - [Sections table](#sections-table)
      - [Import Directory Table](#import-directory-table)
      - [CPP script](#pe-script)
   - [Message Box](#message-box)
      - [CPP script](#message-box-script)
   - [Malware analysis](#malware-analysis)
      - [Setup environment](#setup-environment)
      - [Static analysis](#static-analysis)
      - [Dynamic-analysis](#dynamic-analysis)

---

# PE File

This type of file using for Win32, used on Win32 for almost purpose 

Why we need to know PE file?
 - Injecting code into executable file
 - Manual unpacking product file (being packed)

Get detail with a document [here](/document/PE_tutorial.pdf)

---

## Introduction

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

## DOS Header

Accounting for `first 64 bytes` of file, defined in `window.inc` or `winnt.h`. In PE file, magic of DOS header includes value: `4Dh, 5Ah (2 bytes first)`. `Ifanview` which at the end of DOS header and beginning of DOS stub, is `DWORD` and includes offset of PE header

---

## The PE header

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

## Sections table

Get it from `IMAGE_SECTION_HEADER` which are containers of the actual data:

   - `.text`: Contains the executable code of the program.
   - `.data`: Contains the initialized data.
   - `.bss`: Contains uninitialized data.
   - `.rdata`: Contains read-only initialized data.
   - `.edata`: Contains the export tables.
   - `.idata`: Contains the import tables.
   - `.reloc`: Contains image relocation information.
   - `.rsrc`: Contains resources used by the program, these include images, icons or even embedded binaries.
   - `.tls`: (Thread Local Storage), provides storage for every executing thread of the program.

---

## Import Directory Table

Located at the beginning of the `.idata` section, get it from `IMAGE_IMPORT_DESCRIPTOR`:

   - OriginalFirstThunk: RVA of the ILT
   - TimeDateStamp: A time date stamp, that’s initially set to 0 if not bound and set to 0-1 if bound
   - ForwarderChain: The index of the first forwarder chain reference
   - Name: An RVA of an ASCII string that contains the name of the imported DLL
   - FirstThunk: RVA of the IAT

---

## PE script

Using this [simple CPP program](/script/pe.cpp) to get information from PE file

Using command line: `gcc pe.cpp -o pe.exe` to build EXE file with GCC

Using this program with PowerShell or cmd: `.\pe.exe <path/of/file>`, then result will be similar like this:

*Note: this script only read data of PE32+ file*

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

# Message Box

Program (C/C++) to insert into any EXE file a Message Box **"You've got infected"**. After showing that Message Box, the program continues to run normally.

You write a program to insert a code into EXE file so that when running the modified EXE file, it will turn on the Message Box, after pressing the Ok button on that Message Box, the file continues to run as it was.

To do work:

1. Open file to read and write
2. Extract PE file information
3. Find a suitably-sized code cave (create a new section `.inflect`)
4. Tailor `shellcode` to the target application, using Metasploit framework
5. Acquire any additional data for the `shellcode` to function
6. Inject the `shellcode` into the application
7. Modify the application's original entry point to the start

---

## Message Box Script

Using this [simple CPP program](/script/messagebox.cpp) to infect Message Box into EXE file

Using command line `gcc messagebox.cpp -m32 -std=c++17 -lstdc++fs -o messagebox.exe` to build EXE

**Warning: after compiler built executable file, window defender will detect it is a Trojan, so you just allow it to run**

Using this program with PowerShell or cmd: `.\messagebox.exe <path/of/directory>`, then all EXE file in target directory will be modified with Message Box. Opening modified application to see result as description

*Note: this script only read data of PE32 file*

---

# Malware analysis

Analysis a sample and source code of `LockBit` ransomware on the internet and try to analyze it behaviors both static and dynamic way

Get detail with a document [here](/document/Practical_malware_analysis.pdf)

---

## Setup environment

We need a sandbox environment using virtual machine to make sure hosting machine will be not affected by malware. Just download any window virtual machine from [here](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) or [ISO file](https://www.microsoft.com/en-us/software-download/windows10). In this case, window 10 is selected to main OS virtual machine. 

---

## Static analysis 

Technique using for static analysis:
   - Antivirus tools to confirm maliciousness
   - Hashes to identify malware
   - Gleaning information from a file’s strings, functions, and headers

---

## Dynamic analysis









