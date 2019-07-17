#include <windows.h>
#include <stdint.h>

/* Compile as x64 Release !!! */

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 ) { 

	if (ul_reason_for_call == DLL_PROCESS_ATTACH) { 
		MessageBox(0, L"Done.", L"Injected", MB_OK | MB_ICONERROR);
	}
}


