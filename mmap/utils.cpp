#include "utils.h"

bool is_process_running(const char* process_name, uint32_t& pid) {
	PROCESSENTRY32 process_entry{};
	process_entry.dwSize = sizeof(PROCESSENTRY32);
	pid = 0;
	auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;
	if (Process32First(snapshot, &process_entry)) {
		do {
			if (!strcmp(process_name, process_entry.szExeFile)) {
				pid = process_entry.th32ProcessID;
				CloseHandle(snapshot);
				return true;
			}
		} while (Process32Next(snapshot, &process_entry));
	} 
	CloseHandle(snapshot);
	return false;
}