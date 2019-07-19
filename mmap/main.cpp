#include <iostream>
#include "mmap.hpp"
#include <thread>
#include <chrono>
#include <array>

int main(int argc, char **argv) { 
	mmap mapper(INJECTION_TYPE::KERNEL);

	if (!mapper.attach_to_process("notepad.exe"))
		return 1;

	if (!mapper.load_dll("example_dll.dll"))
		return 1;

	if (!mapper.inject())
		return 1;

	std::cout << "\nPress any key to close.\n";
	std::getchar();
	 
	return 0;
}