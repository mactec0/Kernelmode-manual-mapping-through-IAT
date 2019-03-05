#include "process.hpp"

bool c_process::find_by_name(const char* process_name, uint32_t& pid) {
	PROCESSENTRY32 process_entry{};
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	pid = 0;

	auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };

	if (!snapshot)
		return false;

	if (Process32First(snapshot, &process_entry)){
		do {
			if (!strcmp(process_name, process_entry.szExeFile)) {
				pid = process_entry.th32ProcessID;
				CloseHandle(snapshot);
				return true;
			}
		}
		while (Process32Next(snapshot, &process_entry));
	}

	CloseHandle(snapshot);
	return false;
}

void c_process::close_handle() {
	if (m_handle)
		CloseHandle(m_handle);
}

bool c_process::is_attached()
{
	return ( m_handle && m_handle != INVALID_HANDLE_VALUE );
}

c_process::c_process() {
	m_name = NULL;
	m_handle = INVALID_HANDLE_VALUE;
	m_pid = 0;
}

c_process::~c_process() {
	CloseHandle(m_handle);
}

bool c_process::attach(const char* process_name) {
	m_name = process_name;

	if (!find_by_name(process_name, m_pid))
		return false;

	m_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, m_pid);

	if (!m_handle || m_handle == INVALID_HANDLE_VALUE)
		return false;

	return true;
}

bool c_process::is_running(const char* process_name) {
	uint32_t pid{};
	return find_by_name(process_name, pid);
}

uint32_t c_process::get_pid() {
	return m_pid;
}

uint64_t c_process::get_process_base() {
	return get_module_base(m_name);
}

uint64_t c_process::get_module_base(const char* module_name) {
	MODULEENTRY32 module_entry;
	HANDLE snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_pid) };
	module_entry.dwSize = sizeof(MODULEENTRY32);
	Module32First(snapshot, &module_entry);
	do {
		if (!_stricmp(module_entry.szModule, module_name))
			return (uint64_t)module_entry.hModule;
		module_entry.dwSize = sizeof(MODULEENTRY32);
	} while (Module32Next(snapshot, &module_entry));
	CloseHandle(snapshot);
	return NULL;
}

uint32_t c_process::virtual_protect(uint64_t address, size_t size, uint32_t new_protect) {
	DWORD old_protect{};
	VirtualProtectEx(m_handle, LPVOID(address), size, new_protect, &old_protect);
	return old_protect;
}

uint64_t c_process::virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, void * addr) {
	void *address{ VirtualAllocEx(m_handle,
		addr,
		size,
		allocation_type,
		protect) };
	return (uint64_t)address;
}

void c_process::load_library(const char* module_name) {
	uint64_t address{ virtual_alloc(0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
	write_memory(address, module_name, strlen(module_name));
	HANDLE thread_handle{ CreateRemoteThread(
		m_handle,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)
		GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"),
		(PVOID)address,
		0,
		NULL) };

	CloseHandle(thread_handle); 
}

uint64_t c_process::get_proc_address(const char* module_name, const char* func) {
	uint64_t remote_module{ get_module_base(module_name) };
	uint64_t local_module{ (uint64_t)GetModuleHandle(module_name) };
	uint64_t delta{ remote_module - local_module }; 
	return ((uint64_t)GetProcAddress((HMODULE)local_module, func) + delta);
}

bool c_process::parse_imports() {
	if (!m_handle || m_handle == INVALID_HANDLE_VALUE)
		return false;

	m_imports.clear();

	auto read_name = [this](uint64_t address) -> std::string {
		char name[256]{};
		ReadProcessMemory(m_handle, LPCVOID(address), &name, 256, NULL);
		return std::string(name);
	};

	auto base{ get_process_base() };

	auto dos_header{ read_memory< IMAGE_DOS_HEADER >(base) };
	auto nt_headers{ read_memory< IMAGE_NT_HEADERS >(base + dos_header.e_lfanew) };
	auto descriptor{ read_memory< IMAGE_IMPORT_DESCRIPTOR >(base + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress) };

	int descriptor_count{ 0 };
	int thunk_count{ 0 };

	while (descriptor.Name) {
		auto descriptor_name{ read_name(base + descriptor.Name) };
		auto first_thunk{ read_memory< IMAGE_THUNK_DATA >(base + descriptor.FirstThunk) };
		auto original_first_thunk{ read_memory< IMAGE_THUNK_DATA >(base + descriptor.OriginalFirstThunk) };

		thunk_count = 0;
		while (original_first_thunk.u1.AddressOfData){
			auto name{ read_name(base + original_first_thunk.u1.AddressOfData + 0x2) };
			auto thunk_offset{ thunk_count * sizeof(uintptr_t) };

			if(name.length() > 0)
				m_imports[descriptor_name].insert(std::make_pair(name, base + descriptor.FirstThunk + thunk_offset));

			++thunk_count;
			first_thunk = read_memory< IMAGE_THUNK_DATA >(base + descriptor.FirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
			original_first_thunk = read_memory< IMAGE_THUNK_DATA >(base + descriptor.OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
		}

		++descriptor_count;
		descriptor = read_memory< IMAGE_IMPORT_DESCRIPTOR >(base + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptor_count);
	}

	return ( m_imports.size() > 0 );
}

void c_process::print_imports() {	
	for (auto & descriptor : m_imports) {
		std::cout << " [+] DESCRIPTOR: " << descriptor.first << "\n";

		for (auto & import : descriptor.second)
			std::cout << " " << std::setw(40) << import.first << " : " << std::hex << import.second << "\n";

		std::cout << "\n";
	}

	std::cout << std::endl;
}

uint64_t c_process::get_import_address(const char* name) {
	for (auto & descriptor : m_imports)
		for (auto & import : descriptor.second)
			if (!strcmp(import.first.c_str(), name))
				return import.second;

	return 0;
}


