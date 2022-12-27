#include <windows.h>
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <path-of-EXE-file>" << endl;
        return 1;
    }

    // Open the PE file
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "Error: Unable to open file " << argv[1] << endl;
        return 1;
    }

    // Map the PE file into memory
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapping == NULL) {
        cerr << "Error: Unable to create file mapping for " << argv[1] << endl;
        CloseHandle(hFile);
        return 1;
    }

    LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (lpBase == NULL) {
        cerr << "Error: Unable to map view of file for " << argv[1] << endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Get the DOS header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "Error: Invalid DOS header" << endl;
        UnmapViewOfFile(lpBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Get the NT headers
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((char*)lpBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        cerr << "Error: Invalid NT headers" << endl;
        UnmapViewOfFile(lpBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Get the optional header
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;

    cout << "Successfully inserted MessageBox into " << argv[1] << endl;

    return 0;
}