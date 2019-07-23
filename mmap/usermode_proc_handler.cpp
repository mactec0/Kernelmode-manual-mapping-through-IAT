#include "usermode_proc_handler.hpp"

usermode_proc_handler::usermode_proc_handler() 
	:handle{ NULL }, pid{ 0 } {}

usermode_proc_handler::~usermode_proc_handler() { if (handle) CloseHandle(handle); }

bool usermode_proc_handler::is_attached() {	return handle; }

bool usermode_proc_handler::attach(const char* proc_name) {
	while (!is_process_running(proc_name, pid))
		std::this_thread::sleep_for(std::chrono::seconds(1));

	handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

	return handle;
}

uint64_t usermode_proc_handler::get_module_base(const std::string &module_name) {
	MODULEENTRY32 module_entry{};
	module_entry.dwSize = sizeof(MODULEENTRY32);
	auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;
	if (Module32First(snapshot, &module_entry)) {
		do {
			if (!_stricmp(module_entry.szModule, module_name.c_str())) {
				CloseHandle(snapshot);
				return (uint64_t)module_entry.hModule;
			}
			module_entry.dwSize = sizeof(MODULEENTRY32);
		} while (Module32Next(snapshot, &module_entry));
	}
	CloseHandle(snapshot);
	return NULL;
}

void usermode_proc_handler::read_memory(uintptr_t src, uintptr_t dst, size_t size) {
	ReadProcessMemory(handle, (LPCVOID)src, (LPVOID)dst, size, NULL);
}

void usermode_proc_handler::write_memory(uintptr_t dst, uintptr_t src, size_t size) {
	WriteProcessMemory(handle, (LPVOID)dst, (LPVOID)src, size, NULL);
}

uint32_t usermode_proc_handler::virtual_protect(uint64_t address, size_t size, uint32_t protect) {
	DWORD old_protect{};
	VirtualProtectEx(handle, (LPVOID)address, size, protect, &old_protect);
	return old_protect;
}

uint64_t usermode_proc_handler::virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address) {
	return (uint64_t)VirtualAllocEx(handle, (void*)address, size, allocation_type, protect);
}