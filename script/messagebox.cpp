#include <iostream>
#include <fstream>
#include <Windows.h>

int main(int argc, char** argv) {
if (argc < 2) {
std::cerr << "Usage: " << argv[0] << " file.exe" << std::endl;
return 1;
}

// Open the file in read-write mode
std::fstream file(argv[1], std::ios::in | std::ios::out | std::ios::binary);
if (!file) {
    std::cout << "Error opening file" << std::endl;
    return 1;
}

// Read the AddressOfEntryPoint field from the header
IMAGE_DOS_HEADER dos_header;
file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
IMAGE_NT_HEADERS nt_headers;
file.seekg(dos_header.e_lfanew);
file.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));
DWORD address_of_entry_point = nt_headers.OptionalHeader.AddressOfEntryPoint;

// Calculate the size of the code that displays the MessageBox and the jump instruction
const int code_size = 21; // size of code that displays MessageBox
const int jmp_size = 5; // size of Jmp instruction

// Seek to the end of the file and write the code that displays the MessageBox and jumps back to the original AddressOfEntryPoint
file.seekp(0, std::ios::end);

// Write the code that displays the MessageBox
file.write("\x68\x00\x00\x00\x00", 5); // push address of message string
file.write("\xB8\x04\x00\x00\x00", 5); // mov eax, 4 (MessageBox)
file.write("\xBB\x01\x00\x00\x00", 5); // mov ebx, 1 (parent window handle)
file.write("\xB9\x00\x00\x00\x00", 5); // mov ecx, address of caption string
file.write("\xFF\xD2", 2); // call eax
file.write("\x68\x00\x00\x00\x00", 5); // push address of original AddressOfEntryPoint
file.write("\xc3", 1); // ret

// Write the jump instruction
DWORD message_box_end = file.tellp(); // get position of end of code that displays MessageBox
file.seekp(message_box_end); // seek to end of code that displays MessageBox
file.write("\xE9", 1); // jmp opcode
DWORD relative_offset = address_of_entry_point - (message_box_end + 4); // calculate relative offset
file.write((char*)&relative_offset, 4); // write relative offset to jump instruction

// Update the AddressOfEntryPoint field in the header to point to the start of the code
file.seekp(dos_header.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint));
DWORD start = file.tellp() - code_size - jmp_size;
file.write((char*)&start, sizeof(start));

// Close the file
file.close();

return 0;
}