#include "mmap.hpp"

bool c_mmap::attach_to_process(const char* process_name) {

	while (!process.is_running(process_name)) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		logger::log("Waiting for process...");
	}

	if (!process.attach(process_name)) {
		logger::log_error("Unable to attach to process!");
		return false;
	}

	logger::log("Attached to process successfully...");
	return true;
}
 
bool c_mmap::load_dll(const char* file_name) {
	std::ifstream f(file_name, std::ios::binary | std::ios::ate);

	if (!f) {
		logger::log_error("Unable to open DLL file!");
		return false;
	}

	std::ifstream::pos_type pos{ f.tellg() };
	data_size = pos; 

	raw_data = new uint8_t[data_size];

	if (!raw_data)
		return false;

	f.seekg(0, std::ios::beg);
	f.read((char*)raw_data, data_size);
	 
	f.close();
	return true;
}
  
bool c_mmap::inject() {

	if (!process.is_attached()) {
		logger::log_error("Not attached to process!");
		return false;
	}

	if (!raw_data) {
		logger::log_error("Data buffer is empty!");
		return false;
	}


	uint8_t dll_stub[] = { "\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3" };

	/*
		dll_stub:
		00000000  51                push rcx
		00000001  52                push rdx
		00000002  55                push rbp
		00000003  56                push rsi
		00000004  53                push rbx
		00000005  57                push rdi
		00000006  4150              push r8
		00000008  4151              push r9
		0000000A  4152              push r10
		0000000C  4153              push r11
		0000000E  4154              push r12
		00000010  4155              push r13
		00000012  4156              push r14
		00000014  4157              push r15
		00000016  4883EC28          sub rsp,byte +0x28
		0000001A  48B9DEADBEEFDEAD  mov rcx,0xefbeaddeefbeadde
				 -BEEF
		00000024  4831D2            xor rdx,rdx
		00000027  4883C201          add rdx,byte +0x1
		0000002B  48B8DEADC0DEDEAD  mov rax,0xdec0addedec0adde
				 -C0DE
		00000035  FFD0              call rax
		00000037  4883C428          add rsp,byte +0x28
		0000003B  415F              pop r15
		0000003D  415E              pop r14
		0000003F  415D              pop r13
		00000041  415C              pop r12
		00000043  415B              pop r11
		00000045  415A              pop r10
		00000047  4159              pop r9
		00000049  4158              pop r8
		0000004B  5F                pop rdi
		0000004C  5B                pop rbx
		0000004D  5E                pop rsi
		0000004E  5D                pop rbp
		0000004F  5A                pop rdx
		00000050  59                pop rcx
		00000051  4831C0            xor rax,rax
		00000054  C3                ret
	*/

	IMAGE_DOS_HEADER *dos_header{ (IMAGE_DOS_HEADER *)(&raw_data[0]) };

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		logger::log_error("Invalid DOS header signature!");
		return false;
	}

	IMAGE_NT_HEADERS *nt_header{ (IMAGE_NT_HEADERS *)(&raw_data[dos_header->e_lfanew]) };

	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		logger::log_error("Invalid NT header signature!");
		return false;
	}

	uint64_t base{ process.virtual_alloc(nt_header->OptionalHeader.SizeOfImage,
										  MEM_COMMIT | MEM_RESERVE,
										  PAGE_EXECUTE_READWRITE) };

	if (!base) {
		logger::log_error("Unable to allocate memory for the image!");
		return false;
	}

	logger::log_address("Image base", base);

	uint64_t stub_base{ process.virtual_alloc(sizeof(dll_stub),
											   MEM_COMMIT | MEM_RESERVE,
											   PAGE_EXECUTE_READWRITE) };

	if (!stub_base) {
		logger::log_error("Unable to allocate memory for the stub!");
		return false;
	}

	logger::log_address("Stub base", stub_base);

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor{ (PIMAGE_IMPORT_DESCRIPTOR)get_ptr_from_rva(
												 (uint64_t)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
													nt_header,
													raw_data) };

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		logger::log("Solving imports...");
		solve_imports(raw_data, nt_header, import_descriptor);
	}

	PIMAGE_BASE_RELOCATION base_relocation{ (PIMAGE_BASE_RELOCATION) get_ptr_from_rva(
																		nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
																		nt_header, 
																		raw_data)};

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		logger::log("Solving relocations...");

		solve_relocations((uint64_t) raw_data,
						  base,
						  nt_header,
						  base_relocation,
						  nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	}

	 
	if (!process.parse_imports()) {
		logger::log_error("Unable to parse imports!");
		return false;
	} 

	auto restore_offset{ find_pattern(raw_data, data_size, "DE AD BE EF DE AD BE EF ? ? AF AF AF AF AF AF AF AF") };

	logger::log_address("Restore offset", restore_offset);

	uint64_t iat_function_ptr{ process.get_import_address("TranslateMessage") };
	uint64_t orginal_function_addr{ process.read_memory<uint64_t>(iat_function_ptr) };

	logger::log_address("IAT function pointer", iat_function_ptr);

	*(uint64_t*)(&raw_data[restore_offset]) = orginal_function_addr;
	*(uint64_t*)(&raw_data[restore_offset] + 0x0A) = iat_function_ptr;
	
	process.write_memory(base, raw_data, nt_header->FileHeader.SizeOfOptionalHeader + sizeof(nt_header->FileHeader) + sizeof(nt_header->Signature));

	logger::log("Mapping PE sections...");
	map_pe_sections(base, nt_header);

	uint64_t entry_point{ (uint64_t)base + nt_header->OptionalHeader.AddressOfEntryPoint };
	*(uint64_t*)(dll_stub + 0x1c) = (uint64_t)base;
	*(uint64_t*)(dll_stub + 0x2d) = entry_point;

	logger::log_address("Entry point", entry_point);
	
	process.write_memory(stub_base, (LPVOID)dll_stub, sizeof(dll_stub));
	process.write_protect(iat_function_ptr, (uint64_t)stub_base);

	logger::log("Injected successfully!");

	delete [] raw_data;

	return true;
} 

uint64_t* c_mmap::get_ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS * nt_header, uint8_t * image_base) {
	PIMAGE_SECTION_HEADER section_header{ get_enclosing_section_header(rva, nt_header) };

	if (!section_header)
		return 0; 

	int64_t delta{ (int64_t)(section_header->VirtualAddress - section_header->PointerToRawData) };
	return (uint64_t*)(image_base + rva - delta);
}

PIMAGE_SECTION_HEADER c_mmap::get_enclosing_section_header(DWORD64 rva, PIMAGE_NT_HEADERS nt_header) {
	PIMAGE_SECTION_HEADER section{ IMAGE_FIRST_SECTION(nt_header) }; 

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++) {

		DWORD64 size{ section->Misc.VirtualSize };
		if (!size)
			size = section->SizeOfRawData;

		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + size)))
			return section;
	} 

	return 0;
}
  
void c_mmap::solve_imports(uint8_t *base, IMAGE_NT_HEADERS *nt_header, IMAGE_IMPORT_DESCRIPTOR *import_descriptor) {
	char* module;

	while ((module = (char *)get_ptr_from_rva((DWORD64)(import_descriptor->Name), nt_header, (PBYTE)base))) {
		HMODULE local_module{ LoadLibrary(module) };
		/*dll should be compiled statically to avoid loading new libraries
		if (!process.get_module_base(module)) {
				process.load_library(module);
		}*/
		
		IMAGE_THUNK_DATA *thunk_data{ (IMAGE_THUNK_DATA *)get_ptr_from_rva((DWORD64)(import_descriptor->FirstThunk), nt_header, (PBYTE)base) };

		while (thunk_data->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME *iibn{ (IMAGE_IMPORT_BY_NAME *)get_ptr_from_rva((DWORD64)((thunk_data->u1.AddressOfData)), nt_header, (PBYTE)base) };
			thunk_data->u1.Function = (uint64_t)(process.get_proc_address(module, (char *)iibn->Name));
			thunk_data++;
		}

		import_descriptor++;
	} 

	return;
}
 
void c_mmap::solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS * nt_header, IMAGE_BASE_RELOCATION * reloc, size_t size) {
	uint64_t image_base{ nt_header->OptionalHeader.ImageBase };
	uint64_t delta{ relocation_base - image_base };
	unsigned int bytes{ 0 };  

	while (bytes < size) {

		uint64_t *reloc_base{ (uint64_t *)get_ptr_from_rva((uint64_t)(reloc->VirtualAddress), nt_header, (PBYTE)base) };
		auto num_of_relocations{ (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD) };
		auto reloc_data = (uint16_t*)((uint64_t)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (unsigned int i = 0; i < num_of_relocations; i++) {
			if (((*reloc_data >> 12) & IMAGE_REL_BASED_HIGHLOW))
				*(uint64_t*)((uint64_t)reloc_base + ((uint64_t)(*reloc_data & 0x0FFF))) += delta;
			reloc_data++;
		}

		bytes += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION *)reloc_data;
	}

	return;
}

void c_mmap::map_pe_sections(uint64_t base, IMAGE_NT_HEADERS * nt_header) {
	auto header{ IMAGE_FIRST_SECTION(nt_header) };
	size_t virtual_size{ 0 };
	size_t bytes{ 0 }; 

	while(nt_header->FileHeader.NumberOfSections&&(bytes<nt_header->OptionalHeader.SizeOfImage)) {

		process.write_memory(base + header->VirtualAddress, (LPCVOID)(raw_data + header->PointerToRawData), header->SizeOfRawData); 
		virtual_size = header->VirtualAddress; 
		virtual_size = (++header)->VirtualAddress - virtual_size;
		bytes += virtual_size;

		/*
			TODO:
			Add page protection
		*/
	}

	return;
}

uint64_t c_mmap::find_pattern(uint8_t * data, size_t data_size, uint8_t* pattern, const char* mask) {
	auto pattern_size = strlen(mask);

	for (size_t i = 0; i < data_size-pattern_size; i++) {

		bool pattern_found = true;

		for (size_t j = 0; pattern_found && (j < pattern_size); j++) {
			if (mask[j] == 'x' && data[i + j] != pattern[j]) 
				pattern_found = false;
		}

		if (pattern_found)
			return i;

	}

	return 0;
}

uint64_t c_mmap::find_pattern(uint8_t *data, size_t data_size, const char *ida_pattern) {
	std::stringstream ss{ ida_pattern };
	std::string pattern = "", mask = "";
	std::string byte;
	
	while (ss >> byte) {

		if (byte == "?") {
			pattern += 0xff;
			mask += '?';
		}
		else {
			pattern += (char)strtol(byte.c_str(), NULL, 16);
			mask += 'x';
		}

	}

	return find_pattern(data, data_size, (uint8_t*)pattern.c_str(), (char*)mask.c_str());
}
