#include <cstdio>

#define LOG_ERROR(str, ...) fprintf(stderr,"ERROR: " str "\n", ##__VA_ARGS__)

#define LOG(str, ...) fprintf(stdout, str "\n", ##__VA_ARGS__)
