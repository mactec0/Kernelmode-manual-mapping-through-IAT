#include "logger.hpp"

void logger::log(const std::string& message) {
	std::cout << message << std::endl;
}

void logger::log_error(const std::string& message) {
	std::cout << "ERROR: " << message << std::endl;
}

void logger::log_address(const std::string& name, uint64_t address) {
	std::cout << name << ": 0x" << std::hex << address << std::endl;
}