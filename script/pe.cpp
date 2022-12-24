#include <iostream>
#include <windows.h>

using namespace std;

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
  // Get the import table (not woking)
  PIMAGE_DATA_DIRECTORY pImportTable = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpBase + pImportTable->VirtualAddress);
  for (; pImportDesc->Name != 0; pImportDesc++) {
    cout << "DLL name: " << (char*)((BYTE*)lpBase + pImportDesc->Name) << endl;
    // Get the import address table
    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)lpBase + pImportDesc->FirstThunk);
    // Get the import name table
    PIMAGE_THUNK_DATA pName = (PIMAGE_THUNK_DATA)((BYTE*)lpBase + pImportDesc->OriginalFirstThunk);
    for (; pThunk->u1.Function != 0; pThunk++, pName++) {
      if (IMAGE_SNAP_BY_ORDINAL(pName->u1.Ordinal)) {
        cout << " Ordinal: " << IMAGE_ORDINAL(pName->u1.Ordinal) << endl;
      } else {
        PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)lpBase + pName->u1.AddressOfData);
        cout << " Function name: " << pImportName->Name << endl;
      }
    }
  }
  // Unmap the PE file
  UnmapViewOfFile(lpBase);
  CloseHandle(hMapping);
  CloseHandle(hFile);

  return 0;
}
