#include <iostream>
#include <windows.h>

using namespace std;

// Converts an RVA to a VA
LPVOID RvaToVa(LPVOID lpBase, DWORD dwRva) {
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

  for (unsigned int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
    DWORD dwSectionStartRva = pSectionHeader->VirtualAddress;
    DWORD dwSectionEndRva = dwSectionStartRva + max(pSectionHeader->SizeOfRawData, pSectionHeader->Misc.VirtualSize);
    if (dwRva >= dwSectionStartRva && dwRva < dwSectionEndRva) {
      DWORD dwDelta = pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData;
      return (LPVOID)((BYTE*)lpBase + dwRva - dwDelta);
      }
  }
  return NULL;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    cerr << "Usage: " << argv[0] << " <path-of-PE-file>" << endl;
    return 1;
  }

  // Open the PE file
  HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    cerr << "Error: Unable to open file " << argv[1] << endl;
    return 1;
  }

  // Map the PE file into memory
  HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hMapping == NULL) {
    cerr << "Error: Unable to create file mapping for " << argv[1] << endl;
    CloseHandle(hFile);
    return 1;
  }

  LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
  if (lpBase == NULL) {
    cerr << "Error: Unable to map view of file for " << argv[1] << endl;
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 1;
  }

  // Get the DOS header
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    cerr << "Error: Invalid DOS signature in " << argv[1] << endl;
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 1;
  }

  // Get the NT headers
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    cerr << "Error: Invalid NT signature in " << argv[1] << endl;
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 1;
  }

  cout << endl << "== Information of file ==" << endl;
  // Get the NT headers
  DWORD PointerToEntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
  cout << "PointerToEntryPoint: " << dec << PointerToEntryPoint << endl;
  DWORD CheckSum = pNtHeaders->OptionalHeader.CheckSum;
  cout << "CheckSum: " << dec << CheckSum << endl;
  DWORD ImageBase = pNtHeaders->OptionalHeader.ImageBase;
  cout << "ImageBase: " << dec << ImageBase << endl;
  DWORD FileAlignment = pNtHeaders->OptionalHeader.FileAlignment;
  cout << "FileAlignment: " << dec << FileAlignment << endl;
  DWORD SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
  cout << "SizeOfImage: " << dec << SizeOfImage << endl;
  cout << "----------------------------------------" << endl << endl;

  cout << "== Information of sections ==" << endl;
  // Get the section headers
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
  for (unsigned int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
    cout << "Name: " << pSectionHeader->Name << endl;
    cout << " Characteristics: " << dec << pSectionHeader->Characteristics << endl;
    cout << " RawAddress: " << dec << pSectionHeader->PointerToRawData << endl;
    cout << " RawSize: " << dec << pSectionHeader->SizeOfRawData << endl;
    cout << " VirtualAddress: " << dec << pSectionHeader->VirtualAddress << endl;
    cout << " VirtualSize: " << dec << pSectionHeader->Misc.VirtualSize << endl;
    cout << "----------------------------------------" << endl << endl;
  }

  cout << endl << "== Information of imports ==" << endl;
   // Get the address of the import directory table
  PIMAGE_DATA_DIRECTORY pImportDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToVa(lpBase, pImportDirectory->VirtualAddress);

  // Iterate through the import directory table
  while (pImportDescriptor->Name != 0) {
    // Get the name of the imported module
    PSTR pszModuleName = (PSTR)RvaToVa(lpBase, pImportDescriptor->Name);

    cout << "Imported module: " << pszModuleName << endl;

    // Get the ILT and INT for this module
    PIMAGE_THUNK_DATA pImportLookupTable = (PIMAGE_THUNK_DATA)RvaToVa(lpBase, pImportDescriptor->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pImportNameTable = (PIMAGE_THUNK_DATA)RvaToVa(lpBase, pImportDescriptor->FirstThunk);

    // Iterate through the ILT and INT
    while (pImportLookupTable->u1.AddressOfData != 0) {
      // Check if the entry in the ILT is an RVA or an ordinal
      if (pImportLookupTable->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        // Entry is an ordinal
        WORD wOrdinal = IMAGE_ORDINAL(pImportLookupTable->u1.Ordinal);
        cout << "  Imported function (ordinal): " << dec << wOrdinal << endl;
      } else {
        // Entry is an RVA
        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToVa(lpBase, pImportLookupTable->u1.AddressOfData);
        cout << "  Imported function (name): " << pImportByName->Name << endl;
      }

      // Move to the next entry in the ILT and INT
      pImportLookupTable++;
      pImportNameTable++;
    }

    // Move to the next imported module
    pImportDescriptor++;
  }

  // Unmap the PE file
  UnmapViewOfFile(lpBase);
  CloseHandle(hMapping);
  CloseHandle(hFile);

  return 0;
}
