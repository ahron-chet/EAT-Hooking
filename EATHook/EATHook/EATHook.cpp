#include <Windows.h>
#include <iostream>






constexpr size_t ALLOC_SIZE_FOR_JMP = 12;
constexpr size_t ALLOC_JUMP_64KB = 0x10000;

typedef HMODULE(WINAPI* LoadLibraryWType)(LPCWSTR);

struct EAT_FUNCTION_INFO
{
    DWORD* pAddressOfFunctions;
    DWORD* pAddressOfNames;
    WORD* pAddressOfNameOrdinals;
    DWORD numberofFunctions;
};

void CreateAbsoluteJump(PVOID source, PVOID target) {
    LPBYTE p = (LPBYTE)source;
    p[0] = 0x48;  // REX.W prefix
    p[1] = 0xB8;  // MOV RAX, imm64 
    memcpy(p + 2, &target, 8);  // Copy the target function address to the instruction
    p[10] = 0xFF; // JMP 
    p[11] = 0xE0; // JMP RAX 
}



PVOID Allocateafterbase(PIMAGE_NT_HEADERS64 pNtHeaders, HMODULE hMod, const size_t size) {
    DWORD64 allocAddress = pNtHeaders->OptionalHeader.SizeOfImage + (DWORD_PTR)hMod;

    PVOID allocatedAddress;

    do {
        allocatedAddress = VirtualAlloc((PVOID)allocAddress, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        allocAddress += ALLOC_JUMP_64KB;
    } while (allocatedAddress == nullptr);

    return allocatedAddress;
}


void getHeaders(HMODULE hMod, IMAGE_DOS_HEADER** pDosHeader, PIMAGE_NT_HEADERS64* pNtHeaders) {
    *pDosHeader = (IMAGE_DOS_HEADER*)hMod;
    *pNtHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)hMod + (*pDosHeader)->e_lfanew);

}


void getFunctionAddresses(PIMAGE_NT_HEADERS64 pNtHeaders, HMODULE hMod, EAT_FUNCTION_INFO* pEatainf) {

    DWORD eata = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)((LPBYTE)hMod + eata);
    pEatainf->numberofFunctions = ExportDir->NumberOfNames;
    pEatainf->pAddressOfFunctions = (DWORD*)((LPBYTE)hMod + ExportDir->AddressOfFunctions);
    pEatainf->pAddressOfNames = (DWORD*)((LPBYTE)hMod + ExportDir->AddressOfNames);
    pEatainf->pAddressOfNameOrdinals = (WORD*)((LPBYTE)hMod + ExportDir->AddressOfNameOrdinals);
}


void Hooking(char* targetFunc, HMODULE hMod, PVOID hookM, EAT_FUNCTION_INFO* pEatainf, PIMAGE_NT_HEADERS64 pNtHeaders) {

    for (DWORD i = 0; i < pEatainf->numberofFunctions; i++) {
        char* funcName = (char*)((LPBYTE)hMod + pEatainf->pAddressOfNames[i]);
        // std::cout << funcName << "\n";
        if (strcmp(funcName, targetFunc) == 0) {
            DWORD* functionRVAAddr = &pEatainf->pAddressOfFunctions[pEatainf->pAddressOfNameOrdinals[i]];
            DWORD oldProtect;
            if (VirtualProtect(functionRVAAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect))
            {
                std::cout << "Original Function Address: " << std::hex << (PVOID)((LPBYTE)hMod + *functionRVAAddr) << "\n";
                std::cout << "Original RVA: " << *functionRVAAddr << std::hex << "\n";

                PVOID newHook = Allocateafterbase(pNtHeaders, hMod, ALLOC_SIZE_FOR_JMP);

                std::cout << "Address of hooked function: " << newHook << std::hex << "\n";
                CreateAbsoluteJump(newHook, hookM);

                while ((PVOID)((LPBYTE)hMod + *functionRVAAddr) != newHook) {
                    *functionRVAAddr += 1;
                }
                std::cout << "Updated RVA: " << *functionRVAAddr << std::hex << "\n";

                VirtualProtect(functionRVAAddr, sizeof(DWORD), oldProtect, &oldProtect);

                std::cout << "Updated Function Address: " << (PVOID)((LPBYTE)hMod + *functionRVAAddr) << std::hex << "\n";
                break;
            }
        }
    }
}


void printHooked() {
    printf("Hello From hooked function!!\n");
}


int main() {

    PVOID hookM = (PVOID)printHooked;
    HMODULE hKrrnl32 = LoadLibrary(L"kernel32.dll");
    HMODULE hMod = GetModuleHandleA("kernel32.dll");

    char targetFunc[13] = "LoadLibraryW";

    IMAGE_DOS_HEADER* pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeaders;

    getHeaders(hMod, &pDosHeader, &pNtHeaders);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Failed to get headers. Module doesn't match NT signature";
        return 0;
    }


    EAT_FUNCTION_INFO* pEatainf = new EAT_FUNCTION_INFO{};
    getFunctionAddresses(pNtHeaders, hMod, pEatainf);


    std::cout << "Module Base Address: " << hMod << std::hex << "\n";

    Hooking(targetFunc, hMod, hookM, pEatainf, pNtHeaders);

    LoadLibraryWType pLoadLibrary = (LoadLibraryWType)GetProcAddress(hKrrnl32, "LoadLibraryW");
    std::cout << "Function addres after hook: " << pLoadLibrary << std::hex << "\n";
    HMODULE hAnotherDLL = pLoadLibrary(L"AnotherDLL.dll");
    delete[] pEatainf;
}


