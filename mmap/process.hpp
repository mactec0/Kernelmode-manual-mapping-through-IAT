#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>
#include <map>
#include <iostream>
#include <string>
#include <iomanip>

class c_process
{
private:
	const char* m_name;
	HANDLE	m_handle;
	uint32_t m_pid;

	std::map<std::string, std::map<std::string, uint64_t>> m_imports;

public: 

	c_process();
	~c_process();

	bool attach(const char* process_name);
	bool is_running(const char* process_name);
	void close_handle();

	bool is_attached();

	uint32_t get_pid();
	uint64_t get_process_base();
	uint64_t get_module_base(const char* module_name);
	uint32_t virtual_protect(uint64_t address, size_t size, uint32_t new_protect);
	uint64_t virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, void *addr = NULL);
	void load_library(const char* module_name);

	uint64_t get_proc_address(const char *module_name, const char *func);

	bool parse_imports();
	void print_imports();
	uint64_t get_import_address(const char* name);

	template <typename T>
	T read_memory(uint64_t address)
	{
		T buffer{ };
		ReadProcessMemory(m_handle, LPVOID(address), &buffer, sizeof(T), NULL);
		return buffer;
	}

	template <typename T>
	void write_memory(uint64_t address, T value)
	{
		WriteProcessMemory(m_handle, LPVOID(address), &value, sizeof(T), NULL);
	}
	
	void write_memory(uint64_t address, LPCVOID value, size_t size)
	{ 
		WriteProcessMemory(m_handle, LPVOID(address), value, size, NULL);
	}

	template <class T>
	void write_protect(uint64_t address, T value)
	{
		uint32_t old_protect = virtual_protect(address, sizeof(T), PAGE_READWRITE);
		write_memory(address, value);
		virtual_protect(address, sizeof(T), old_protect);
	}

private:

	bool find_by_name(const char* process_name, uint32_t& pid);
};