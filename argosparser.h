
#ifndef ARGOSPARSER_20080820_H_
#define ARGOSPARSER_20080820_H_

#include <stdint.h>	// unfortunately, not all compilers support this header :-(

struct arch_spec_x86 {
	static const int NUM_REGS = 8;
	typedef uint32_t address_t;
	
	static const char *const register_names[NUM_REGS];
};

struct arch_spec_x86_64 {
	static const int NUM_REGS = 16;
	typedef uint64_t address_t;
	
	static const char *const register_names[NUM_REGS];
}; 

#endif
