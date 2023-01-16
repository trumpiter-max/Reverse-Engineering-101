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
      - [Malware description](#malware-description)
         - [Static result](#static)
            - [General view](#general)
            - [Build File](#build-file)
         - [Dynamic result](#dynamic)

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

*Note: this script only read data of PE32 file only*

---

# Malware analysis

Analysis a sample and source code of `LockBit` ransomware on the internet and try to analyze it behaviors both static and dynamic way

Get details from document [here](/document/Practical_malware_analysis.pdf)

---

## Setup environment

We need a sandbox environment using virtual machine to make sure hosting machine will be not affected by malware. Just download any window virtual machine from [here](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) or [ISO file](https://www.microsoft.com/en-us/software-download/windows10). In this case, [`FlareVM`](https://github.com/mandiant/flare-vm) (Window Based Reverse Engineering and Malware Analysis Platform) is selected to main OS virtual machine. Using `Host-only` virtual network card to prevent threat of malware.

Using [VMware](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html) (recommended) or [Virtual Box](https://www.virtualbox.org/wiki/Downloads). Configure virtual machine before analyzing malware, choose custom network card to make virtual network, often take snapshot for machine when get sample of malware

*Note: should avoid performing malware analysis on any critical or sensitive machine and keep virtual machine software up-to-dated*

---

## Static analysis 

Describe the process of analyzing the code or structure of a program to determine its 
function

Technique using for static analysis:
   - `Antivirus tools` to confirm maliciousness
      - Known suspicious code (`file signatures`) 
      - Pattern-matching analysis (`heuristics`) 
   - `Hashes` to identify malware
      - Commonly used is `MD5` or `SHA-1`
      - Using hash as label, share to other to help them to identify malware
   - `Gleaning information` from a `file’s strings, functions, and headers`
      - `Finding Strings`: get hints from ASCII or Unicode format string of program
      - `Packed and Obfuscated Malware`: this technique hide information of malware
         - `Packing file`: using `PEiD program` to detect type of packer then unpack 
      - `Portable Executable File Format`: PE files begin with a header that includes information about the code, 
the type of application, required library functions, and space requirements.
      -` Linked Libraries` and `Functions`: 
         - `Imports` are functions used 
by one program that are actually stored in a different program
         - `Static, Runtime, and Dynamic Linking`: 
            - `Static linking`: used in UNIX and Linux programs that all code from that library is copied into the executable 
            - `Runtime linking`: Executables that use 
runtime linking connect to libraries only when that function is needed
            - Two most commonly used are `LoadLibrary` and `GetProcAddress`. `LdrGetProcAddress` and 
`LdrLoadDll` are also used.
            - `Dynamic linking`: host OS searches for the necessary libraries when the program is loaded. Using `Dependency Walker` to export `Dynamic linking`

---

## Dynamic analysis

`Running Malware`: focus on running the majority of malware, encounter (EXEs and DLLs). Using `rundll32.exe` to provide a cointainer for running a DLL. Malicious DLLs frequently run most of their code in DLLMain (called from the DLL entry point)

`Monitoring` with `Process Monitor` or `procmon`: monitor certain registry, file system, network, process, and thread activity

`Viewing Processes` with `Process Explorer`: provide valuable insight into the processes currently running on a system

Using `Dependency Walker`: determine whether a DLL is loaded into a process after load time, compare the DLL list in Process Explorer to the imports shown in `Dependency Walker`

`Analyzing Malicious Documents`: using `Process Explorer` to analyze malicious documents, such as 
PDFs and Word documents.

Comparing `Registry Snapshots` with `Regshot` to get hint about alternative of window registry

Faking a Network: Malware often beacons out and eventually communicates with a command-and-control server so prevent malware from realizing virtual environment using `ApateDNS` or `FakeNet` then monitor with `netcat`

`Packet Sniffing` with `Wireshark`: intercepts and logs network traffic

Using `INetSim`: simulating common Internet services

---

## Malware description

The sample in this case is `LockBit 3.0` ransomware - designed to block user access to computer systems in exchange for a ransom payment in 2019 and first-ever sample publication in 2022. Exploit Windows Defender to deploy Cobalt Strike, it tricks system to load malicious DLL (Dynamic-Link Library) - sideload method. 

This use the encrypted `Salsa-20 algorithm`. During the encryption threads, memory containing the private key is protected with heavy use of `RtlEncryptMemory` and `RtlDecyptMemory`, which makes the private key available unencrypted in memory only for the time it is necessary.

Get sample for this case at [here](https://github.com/whichbuffer/Lockbit-Black-3.0). Make sure safety environment is ready, then download it and unzip

Furthermore, get build file of `LockBit Black` at [here](https://web.archive.org/web/20220922061814if_/https://raw.githubusercontent.com/3xp0rt/LockBit-Black-Builder/main/LockBit3Builder.7z) and password for unzip is: `!1C!Vk~1i!LW3LR|wgXHC`, md5 hash of file: `7db3797ee09aedc1c6ec1389ab199493`. After unzip file, we get below files:

![Build file](https://i.ibb.co/w4VzkLf/Screenshot-20230111-105046.png)

*Note: this repo storing this source are disabled, only use for educational purpose*

---

### Static

#### General

Using `DIE (Detect it easy)` to find file type of malware 

![PE type](https://i.ibb.co/ZLvHh9Q/Screenshot-20230109-095845.png)

![File status](https://i.ibb.co/NnNCTPS/Screenshot-20230110-102021.png)

![Import table](https://i.ibb.co/znphXHN/Screenshot-20230110-101717.png)
It is a `PE32` file using `Microsoft Linker (14.12)[GUI32]` and its import table includes: 
   - `gdi32.dll`: contain functions for displaying and manipulating graphics
      - TextOutW
      - SetTextColor
      - SetPixel
      - SelectObject
      - GetTextMetricsW
   - `USER32.dll`: contain user-interface components
      - EndDialog
      - GetDigItem
      - GetDigItemTextW
      - GetKeyNameTextW
      - GetMessageW
      - LoadMenuW
      - DialogBoxParamW
      - CreateWindowExW 
      - CreateDialogParamW
      - GetClassNameW
   - `KERNEL32.dll`: contain core functionality
      - GetDateFormatW
      - LoadLibraryExA
      - GetTickCount
      - GetProcAddress
      - GetModuleHandleW
      - GetLocateInfoW
      - GetCommandLineA
      - FormatMessageW
      - GetLastError 
   
Moreover, in string of file, it has string `!This program cannot be run in DOS mode` - meaning that current running `Windows NASM`on an MS-DOS (virtual) platform

Continue to use `HashCalc` to hash file:

![Hash result](https://i.ibb.co/M2Mt0cT/Screenshot-20230110-104250.png)

This file has:
   - `MD5` hash: `38745539b71cf201bb502437f891d799`
   - `SHA1` hash: `f2a72bee623659d3ba16b365024020868246d901` 

Then go to website [`VirusTotal`](https://www.virustotal.com/) at host machine, find with hash, or see the result at [here](https://www.virustotal.com/gui/file/80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce)

![AV result](https://i.ibb.co/vqTMRvg/Screenshot-20230110-105049.png)

We can see some useful details:

![Contact IP](https://i.ibb.co/yy4f5hC/Screenshot-20230111-112031.png)

![IP Graph](https://i.ibb.co/v3BKX64/Screenshot-20230111-111910.png)

Find more details with [`any.run`](https://app.any.run/) at [here](https://app.any.run/tasks/aae15060-a25d-4846-bdae-4b2515129b2e/)

### Build file

Lock at [`config.json`](/malware_analysis_note/config.txt) and [`build.bat`](/malware_analysis_note/build.txt) first in source code, there are a lot of actions when malware run

Using `ResourceHacker` to look inside file `build.exe`, and description of each resource by its ID: 
   - 100: decryption template file 
   - 101: executable template file 
   - 103: DLL template file 
   - 106: DLL template file that enables reflective loading

![Builder](https://i.ibb.co/wQwdgZD/Screenshot-20230113-020610.png)

Try to run `build.bat` to generate files in build folder:
   - `DECRYPTION_ID.txt`:used to uniquely identify a victim 
   - `LB3.exe`: compiled ransomware, which doesn’t require a password 
   - `LB3Decryptor.exe`: decryption for the ransomware
   - `LB3_pass.exe`: same as LB3.exe which require password and instructions in `Password_exe.txt` 
`LB3_RelectiveDLL_DLLMain.dll` 
   - `LB3_Rundll32.dll`: DLL version of ransomware, not require password
   - `LB3_Rundll32_pass.dll`: DLL version of ransomware, require password in `Password_dll.txt` 
   - `Password_dll.txt`: contain password and instructions for using `LB3_Rundll32_pass.dll` 
   - `Password_exe.txt`: contain password and instructions for using `LB3_pass.exe` 
   - `priv.key`: private encryption key used to encrypt victim files 
   - `pub.key`: public encryption key used generate various strings that tie this instance of the ransomware to a victim

Fact of this malware: it uses `Anti-debugging trick` by loading/resolving a Windows DLL from its hash tables, which are based on ROT13 to conceal their internal functions calls and hide the 
function calls and `Windows APIs` by using `Stack String Obfuscation` and simple `XOR Encryption`

---

### Dynamic

Before first run, capture state with `RegShot`: compare state of registry before and after

Click to see below video

[![video](https://i.ibb.co/b64JG0s/Screenshot-20230116-085406.png)](https://streamable.com/fdo2v9)

Following PDF file following in same folder. Using flag `-pass` when running file to decrypt the source code of `LockBit` and execute it on victim:

```
   <Ransomware.exe> -k LocalServiceNetworkRestricted -pass db66023ab2abcb9957fb01ed50cdfa6a
```   

![First run](https://i.ibb.co/TY7Jqfk/Screenshot-20230110-082437.png)

After running malware, it encrypts some files into `<random>.HLJkNskOq` and create multiple note `HLJkNskOq.README.txt`, see content [here](/malware_analysis_note/malware_note.txt) and wallpaper is changed 

![Wallpaper](https://i.ibb.co/GFD5kwP/Screenshot-20230110-090349.png)

Overall, this malware will disable registry of Window Security to prevent its detection and a lot of registries are modifies, see more [here](/malware_analysis_note/regshot.rar). 

Check the status of Window Security with command line: `sc query WinDefend` in cmd

![Window defend status](https://i.ibb.co/4fNn1RK/Screenshot-20230110-085602.png)

Check results in `ProcessMonitor`

![](https://i.ibb.co/xsMNhH2/Screenshot-20230111-094745.png)











