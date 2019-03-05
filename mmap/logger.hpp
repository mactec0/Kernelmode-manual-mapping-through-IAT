#include <iostream>
#include <string>

namespace logger
{
	void log(const std::string& message);
	void log_error(const std::string& message);
	void log_address(const std::string& name, uint64_t value);
}