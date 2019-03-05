#pragma once
#include"process.hpp"
#include <thread>
#include <chrono>
#include <fstream>
#include <string>
#include <sstream>
#include "logger.hpp"

class c_mmap {
	c_process process;
	uint8_t *raw_data;
	size_t data_size;

public:
	bool attach_to_process(const char* process_name);
	bool load_dll(const char* file_name);
	bool inject();

private:
	//https://github.com/martell/pedump/blob/master/common.h
	uint64_t * get_ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS * nt_header, uint8_t * image_base);
	PIMAGE_SECTION_HEADER get_enclosing_section_header(DWORD64 rva, PIMAGE_NT_HEADERS nt_header);

	void solve_imports(uint8_t *base, IMAGE_NT_HEADERS *nt_header, IMAGE_IMPORT_DESCRIPTOR *impDesc);
	void solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS *nt_header, IMAGE_BASE_RELOCATION *reloc, size_t size);
	void map_pe_sections(uint64_t base, IMAGE_NT_HEADERS *nt_header);

	uint64_t find_pattern(uint8_t *data, size_t data_size, uint8_t* pattern, const char *mask);
	uint64_t find_pattern(uint8_t *data, size_t data_size, const char *ida_pattern);
};


