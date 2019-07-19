#pragma once
#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>

bool is_process_running(const char* process_name, uint32_t& pid);