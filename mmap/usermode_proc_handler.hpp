#pragma once
#include "process_handler.hpp"

class usermode_proc_handler final : public process_handler {
	uint32_t pid;
	HANDLE handle;
public:

	virtual bool is_attached() override;

	virtual bool attach(const char* proc_name) override;

	virtual	uint64_t get_module_base(const std::string &module_name) override;

	virtual void read_memory(uintptr_t src, uintptr_t dst, size_t size) override;

	virtual void write_memory(uintptr_t dst, uintptr_t src, size_t size) override; 

	virtual uint32_t virtual_protect(uint64_t address, size_t size, uint32_t protect) override;

	virtual uint64_t virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address = NULL) override;
};