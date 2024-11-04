#include "include/libmem/libmem.hpp"
#include "include/console.hpp"
#include <cstdint>
#include <cstdlib>


int (*o_GetFileVersionInfoA)(const char *lptstrFilename, unsigned long  dwHandle, unsigned long  dwLen, void *lpData);
int (*o_GetFileVersionInfoW)(const wchar_t *lptstrFilename, unsigned long  dwHandle, unsigned long  dwLen, void *lpData);
unsigned long (*o_GetFileVersionInfoSizeA)(const char *lptstrFilename, unsigned long *lpdwHandle);
unsigned long (*o_GetFileVersionInfoSizeW)(const wchar_t *lptstrFilename, unsigned long *lpdwHandle);
int (*o_VerQueryValueA)(const void *pBlock, const char *lpSubBlock, void  **lplpBuffer, unsigned int *puLen);
int (*o_VerQueryValueW)(const void *pBlock, const wchar_t *lpSubBlock, void  **lplpBuffer, unsigned int *puLen);

int main();

extern "C"
__declspec(dllexport) int GetFileVersionInfoA(const char *lptstrFilename, unsigned long  dwHandle, unsigned long  dwLen, void *lpData){
	if(!o_GetFileVersionInfoA) main();
	return o_GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);
}

extern "C"
__declspec(dllexport) int GetFileVersionInfoW(const wchar_t *lptstrFilename, unsigned long   dwHandle, unsigned long dwLen, void *lpData){
	if(!o_GetFileVersionInfoW) main();
	return o_GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
}

extern "C"
__declspec(dllexport) unsigned long GetFileVersionInfoSizeA(const char *lptstrFilename, unsigned long *lpdwHandle){
	if(!o_GetFileVersionInfoSizeA) main();
	return o_GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);
}

extern "C"
__declspec(dllexport) unsigned long GetFileVersionInfoSizeW(const wchar_t *lptstrFilename, unsigned long *lpdwHandle){
	if(!o_GetFileVersionInfoSizeW) main();
	return o_GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
}

extern "C"
__declspec(dllexport) int VerQueryValueA(const void *pBlock, const char *lpSubBlock, void  **lplpBuffer, unsigned int *puLen){
	if(!o_VerQueryValueA) main();
	return o_VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
}

extern "C"
__declspec(dllexport) int VerQueryValueW(const void *pBlock, const wchar_t *lpSubBlock, void  **lplpBuffer, unsigned int *puLen){
	if(!o_VerQueryValueW) main();
	return o_VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
}

bool PatchChecksum(){
	auto StellarisModule = libmem::FindModule("stellaris.exe");
	if(!StellarisModule.has_value()){
		printf("%s\n", "stellaris module not found. exiting...");
		return EXIT_FAILURE;
	}
	//todo patch
	auto address = libmem::SigScan("48 8B 12 48 8D 0D ? ? ? ? E8 ? ? ? ? 8B F8", StellarisModule->base, StellarisModule->size);
	if(!address.has_value()){
		printf("%s\n", "Patten not found. exiting...");
		return EXIT_FAILURE;
	}
	uint8_t bytes[7];
	printf("assembly: %s\n", libmem::Disassemble(libmem::ReadMemory(address.value() + 3, bytes, 7)).value().op_str.c_str());
	//libmem::WriteMemory(address.value() + 3, "");

	return EXIT_SUCCESS;
}

int main(){
	InitConsole();
	auto VersionModule = libmem::LoadModule("C:\\Windows\\System32\\version.dll");
	if(!VersionModule.has_value()) {
		printf("version.dll not found. exiting...\n");
		return EXIT_FAILURE;
	}
	auto pGetFileVersionInfoA = libmem::FindSymbolAddress(&VersionModule.value(), "GetFileVersionInfoA");
	auto pGetFileVersionInfoW = libmem::FindSymbolAddress(&VersionModule.value(), "GetFileVersionInfoW");
	auto pGetFileVersionInfoSizeA = libmem::FindSymbolAddress(&VersionModule.value(), "GetFileVersionInfoSizeA");
	auto pGetFileVersionInfoSizeW = libmem::FindSymbolAddress(&VersionModule.value(), "GetFileVersionInfoSizeW");
	auto pVerQueryValueA = libmem::FindSymbolAddress(&VersionModule.value(), "VerQueryValueA");
	auto pVerQueryValueW = libmem::FindSymbolAddress(&VersionModule.value(), "VerQueryValueW");
	if(!pGetFileVersionInfoA.has_value() or !pGetFileVersionInfoSizeA.has_value() or !pVerQueryValueA.has_value()){
		printf("%s\n", "failed to locate symbol in version.dll. exiting...");
		return EXIT_FAILURE;
	}
	o_GetFileVersionInfoA = (int (*)(const char *, unsigned long, unsigned long, void *))pGetFileVersionInfoA.value();
	o_GetFileVersionInfoW = (int (*)(const wchar_t *, unsigned long, unsigned long, void *))pGetFileVersionInfoW.value();
	o_GetFileVersionInfoSizeA = (unsigned long (*)(const char *, unsigned long *))pGetFileVersionInfoSizeA.value();
	o_GetFileVersionInfoSizeW = (unsigned long (*)(const wchar_t *, unsigned long *))pGetFileVersionInfoSizeW.value();
	o_VerQueryValueA = (int (*)(const void *, const char *, void  **, unsigned int *))pVerQueryValueA.value();
	o_VerQueryValueW = (int (*)(const void *, const wchar_t *, void  **, unsigned int *))pVerQueryValueW.value();

	PatchChecksum();
	return EXIT_SUCCESS;
}