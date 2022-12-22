#include <iostream>
#include <fstream>
#include <Windows.h>
#include "Winnt.h"
#include "iosfwd"

using namespace std;

void fileInformation(ifstream& file, IMAGE_NT_HEADERS ntHeaders)
{
    cout << "== File Information ==" << endl;
    cout << "PointerToEntryPoint: 0x" << hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << endl;
    cout << "CheckSum: 0x" << hex << ntHeaders.OptionalHeader.CheckSum << endl;
    cout << "ImageBase: 0x" << hex << ntHeaders.OptionalHeader.ImageBase << endl;
    cout << "FileAlignment: 0x" << hex << ntHeaders.OptionalHeader.FileAlignment << endl;
    cout << "SizeOfImage: 0x" << hex << ntHeaders.OptionalHeader.SizeOfImage << endl;
    cout << "==================================================" << endl << endl;
}

void sectionInformation(ifstream& file, IMAGE_NT_HEADERS ntHeaders)
{
    IMAGE_SECTION_HEADER sectionHeader;

    cout << "== Section Information ==" << endl;
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
    {
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
        cout << "Name: " << sectionHeader.Name << endl;
        cout << "Characteristics: 0x" << hex << sectionHeader.Characteristics << endl;
        cout << "RawAddress: 0x" << hex << sectionHeader.PointerToRawData << endl;
        cout << "RawSize: 0x" << hex << sectionHeader.SizeOfRawData << endl;
        cout << "VirtualAddress: 0x" << hex << sectionHeader.VirtualAddress << endl;
        cout << "VirtualSize: 0x" << hex << sectionHeader.Misc.VirtualSize << endl;
        cout << "--------------------------------------------------" << endl << endl;
    }
    cout << "==================================================" << endl << endl;
}

void importInformation(ifstream& file, IMAGE_NT_HEADERS ntHeaders)
{
    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR importDescriptor;

    if (importDirectory.VirtualAddress == 0)
    {
        cout << "The file does not have an import directory." << endl;
        return;
    }

    cout << "== Import Information ==" << endl;
    file.seekg(importDirectory.VirtualAddress, ios::beg);
    file.read(reinterpret_cast<char*>(&importDescriptor), sizeof(importDescriptor));

    while (importDescriptor.Name != 0)
    {
        cout << "Name: " << importDescriptor.Name << endl;
        cout << "OriginalFirstThunk: 0x" << hex << importDescriptor.OriginalFirstThunk << endl;
        cout << "TimeDateStamp: 0x" << hex << importDescriptor.TimeDateStamp << endl;
        cout << "ForwarderChain: 0x" << hex << importDescriptor.ForwarderChain << endl;
        cout << "FirstThunk: 0x" << hex << importDescriptor.FirstThunk << endl;
        cout << "--------------------------------------------------" << endl << endl;

        file.read(reinterpret_cast<char*>(&importDescriptor), sizeof(importDescriptor));
    }
    cout << "==================================================" << endl << endl;
}

void exportInformation(ifstream& file, IMAGE_NT_HEADERS ntHeaders)
{

    IMAGE_DATA_DIRECTORY exportDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY exportDescriptor;

    // Check if the export directory exists
    if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0)
    {
        cout << "The file does not have an export directory." << endl;
        return;
    }

    // Read the export descriptor
    file.seekg(exportDirectory.VirtualAddress, ios::beg);
    file.read(reinterpret_cast<char*>(&exportDescriptor), sizeof(exportDescriptor));

    cout << "== Export Information ==" << endl;
    cout << "Name: " << exportDescriptor.Name << endl;
    cout << "Base: " << exportDescriptor.Base << endl;
    cout << "NumberOfFunctions: " << exportDescriptor.NumberOfFunctions << endl;
    cout << "NumberOfNames: " << exportDescriptor.NumberOfNames << endl;
    cout << "AddressOfFunctions: 0x" << hex << exportDescriptor.AddressOfFunctions << endl;
    cout << "==================================================" << endl << endl;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        cout << "Usage: .\\PE <path-of-PE-file>" << endl;
        return 1;
    }

    // Open the file in binary mode
    ifstream file(argv[1], ios::binary);
    if (!file.is_open())
    {
        cout << "Failed to open file, try again" << endl;
        return 1;
    }

    // Read in the DOS header
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    // Check the magic number to verify that this is a PE file
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        cout << "Not a valid PE file" << endl;
        return 1;
    }

    // Read in the NT headers
    file.seekg(dosHeader.e_lfanew, ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

    // Check the magic number to verify that this is a PE file
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
    {
        cout << "Not a valid PE file" << endl;
        return 1;
    }

    // Print out information
    fileInformation(file, ntHeaders);
    sectionInformation(file, ntHeaders);
    importInformation(file, ntHeaders);
    exportInformation(file, ntHeaders);

    return 0;
}