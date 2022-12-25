# Reverse Engineering 101

## Table of content
 - [PE file](#pe-file)
    - [Introduction](#introduction)
    - [DOS Header](#dos-header)
    - [CPP script](/script/pe.cpp)
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
    - `File alignment`(512 bytes or 200h): method how to arrange sections in file on disk and size of sector is optimized in `Loading process`
 - `Hmodule`: address where the beginning of file

---

### DOS Header

Accounting for first 64 bytes of file

### MessageBox

Program (C/C++) to insert into any exe file a MessageBox "You've got infected". After showing that MessageBox, the program continues to run normally.

For example: There is a file notepad.exe. You write a program to insert a code into that file so that when running the notepad.exe file, it will turn on the MessageBox, after pressing the Ok button on that MessageBox, the notepad file continues to run as it was.






