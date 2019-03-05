#include <windows.h>
#include <stdint.h>


//In order to avoid inlining, we are disabling optimization
#pragma optimize( "", off )
void  restore(uint64_t address, uint64_t orginal) {
	unsigned long old_protection;
	VirtualProtect((LPVOID)address, sizeof(uint64_t), PAGE_EXECUTE_READWRITE, &old_protection);
	*(uint64_t*)(address) = orginal;
	VirtualProtect((LPVOID)address, sizeof(uint64_t), old_protection, NULL);
}
#pragma optimize( "", on ) 

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 ) { 

	if (ul_reason_for_call == DLL_PROCESS_ATTACH) { 
		MessageBox(0, L"Done.", L"Injected", MB_OK | MB_ICONERROR);
		restore(0xAFAFAFAFAFAFAFAF, 0xEFBEADDEEFBEADDE);
	}
}


