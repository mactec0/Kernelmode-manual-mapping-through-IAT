#pragma once 
#include "process_handler.hpp"
#include "logger.hpp"
#include "utils.h"

#define ioctl_read_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_write_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_get_module_base CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define ioctl_protect_virutal_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define ioctl_allocate_virtual_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


typedef struct _k_get_base_module_request {
	ULONG pid;
	ULONGLONG handle;
	WCHAR name[260];
} k_get_base_module_request, *pk_get_base_module_request;

typedef struct _k_rw_request {
	ULONG pid;
	ULONGLONG src;
	ULONGLONG dst;
	ULONGLONG size; 
} k_rw_request, *pk_rw_request;

typedef struct _k_alloc_mem_request {
	ULONG pid, allocation_type, protect;
	ULONGLONG addr;
	SIZE_T size;
} k_alloc_mem_request, *pk_alloc_mem_request;

typedef struct _k_protect_mem_request {
	ULONG pid, protect;
	ULONGLONG addr;
	SIZE_T size;
} k_protect_mem_request, *pk_protect_mem_request;

class kernelmode_proc_handler final : public process_handler {
	HANDLE handle;
	uint32_t pid;
public:
	kernelmode_proc_handler();

	~kernelmode_proc_handler();

	virtual bool is_attached() override;

	virtual bool attach(const char* proc_name) override;

	virtual	uint64_t get_module_base(const std::string &module_name) override;

	virtual void read_memory(uintptr_t src, uintptr_t dst, size_t size) override;

	virtual void write_memory(uintptr_t dst, uintptr_t src, size_t size) override;

	virtual uint32_t virtual_protect(uint64_t address, size_t size, uint32_t protect) override;

	virtual uint64_t virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address = NULL) override;
};