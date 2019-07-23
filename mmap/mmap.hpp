#pragma once
#include "usermode_proc_handler.hpp"
#include "kernelmode_proc_handler.hpp"
#include <thread>
#include <chrono>
#include <fstream>
#include <string>
#include <sstream>
#include "logger.hpp"

enum INJECTION_TYPE{
	KERNEL,
	USERMODE
};

class mmap {
	std::unique_ptr<process_handler> proc;
	std::string process_name;
	std::map<std::string, uint64_t> imports;
	uint8_t *raw_data;
	size_t data_size;
	
public:
	bool attach_to_process(const char* process_name);
	bool load_dll(const char* file_name);
	bool inject();

	mmap(INJECTION_TYPE type);

private:
	//https://github.com/martell/pedump/blob/master/common.h
	uint64_t * get_ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS * nt_header, uint8_t * image_base);
	PIMAGE_SECTION_HEADER get_enclosing_section_header(uint64_t rva, PIMAGE_NT_HEADERS nt_header);

	void solve_imports(uint8_t *base, IMAGE_NT_HEADERS *nt_header, IMAGE_IMPORT_DESCRIPTOR *impDesc);
	void solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS *nt_header, IMAGE_BASE_RELOCATION *reloc, size_t size);
	void map_pe_sections(uint64_t base, IMAGE_NT_HEADERS *nt_header);


	uint64_t get_proc_address(const char* module_name, const char* func);
	bool parse_imports();

	template <typename type>
	type read_memory(uint64_t src, uint64_t size = sizeof(type)) {
		type ret;
		proc->read_memory(src, (uintptr_t)&ret, size);
		return ret;
	}

};


