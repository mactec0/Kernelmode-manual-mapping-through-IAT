#pragma once
#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>
#include <map>
#include <iostream>
#include <string>
#include <iomanip>
#include <chrono>
#include <thread>
#include "utils.h"

class process_handler { 
public:
	virtual ~process_handler() { };

	virtual bool is_attached() = 0;

	virtual bool attach(const char* proc_name) = 0;

	virtual	uint64_t get_module_base(const std::string &module_name) = 0;

	virtual void read_memory(uintptr_t src, uintptr_t dst, size_t size) = 0;

	virtual void write_memory(uintptr_t dst, uintptr_t src, size_t size) = 0; 

	virtual uint32_t virtual_protect(uint64_t address, size_t size, uint32_t protect) = 0;

	virtual uint64_t virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address = NULL) = 0;
};
