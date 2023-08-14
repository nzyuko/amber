#include <windows.h>

int main(int argc, char const *argv[])
{
    HMODULE k32 = LoadLibrary("USER32.dll");
    GetProcAddress(k32, "VirtualAlloc");

    LPVOID moduleHandle = GetModuleHandle(NULL);
    if (moduleHandle == NULL)
        return 1;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
    PIMAGE_NT_HEADERS32 imageNTHeaders32 = NULL;
    PIMAGE_NT_HEADERS64 imageNTHeaders64 = NULL;
    LPVOID sectionLocation = NULL;

    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
#if defined(__MINGW64__) || defined(_WIN64)
        imageNTHeaders64 = (PIMAGE_NT_HEADERS64)((BYTE *)moduleHandle + dosHeader->e_lfanew);
        sectionLocation = (LPVOID)(&imageNTHeaders64->OptionalHeader) + imageNTHeaders64->FileHeader.SizeOfOptionalHeader;
#else
        imageNTHeaders32 = (PIMAGE_NT_HEADERS32)((BYTE *)moduleHandle + dosHeader->e_lfanew);
        sectionLocation = (LPVOID)(&imageNTHeaders32->OptionalHeader) + imageNTHeaders32->FileHeader.SizeOfOptionalHeader;
#endif
    }

    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;

    for (int i = 0; i < (imageNTHeaders32 ? imageNTHeaders32->FileHeader.NumberOfSections : imageNTHeaders64->FileHeader.NumberOfSections); i++)
    {
        sectionHeader++;
    }

    unsigned char *buffer = (unsigned char *)VirtualAlloc(NULL, sectionHeader->SizeOfRawData, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (buffer)
    {
        LPVOID sectionDataAddress = (LPVOID)((DWORD_PTR)sectionHeader->VirtualAddress + (imageNTHeaders32 ? imageNTHeaders32->OptionalHeader.ImageBase : imageNTHeaders64->OptionalHeader.ImageBase));
        memcpy(buffer, sectionDataAddress, sectionHeader->SizeOfRawData);
        ((void (*)())buffer)();
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    return 0;
}
