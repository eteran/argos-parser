
#include "argosparser.h"
#include <iostream>
#include <fstream>
#include <ostream>
#include <iomanip>
#include <sstream>
#include <cassert>
#include <cstring>
#include <cstdlib>

bool g_print_only_tainted = false;
bool g_show_shellcode = false;

const char *const arch_spec_x86::register_names[arch_spec_x86::NUM_REGS] = {
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
};

const char *const arch_spec_x86_64::register_names[arch_spec_x86_64::NUM_REGS] = {
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8 ", "r9 ", "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char *const argos_alert_names[] = {
	"ARGOS_ALERT_JMP", 
	"ARGOS_ALERT_P_JMP",
	"ARGOS_ALERT_TSS", 
	"ARGOS_ALERT_CALL", 
	"ARGOS_ALERT_RET", 
	"ARGOS_ALERT_CI", 
	"ARGOS_ALERT_R_IRET", 
	"ARGOS_ALERT_SYSEXIT", 
	"ARGOS_ALERT_SYSRET",
	"ARGOS_ALERT_R_JMP", 
	"ARGOS_ALERT_P_CALL", 
	"ARGOS_ALERT_R_CALL",
	"ARGOS_ALERT_P_IRET"
};

#pragma pack (push, 1)
template<class T>
struct ArgosMemoryBlockHeader {
	typedef T						arch_spec;
	typedef typename T::address_t	address_t;

	static const int VERSION	= 1;
		
	uint8_t			format;
	uint8_t			tainted;
	uint16_t		size;
	address_t		paddr;
	address_t		vaddr;
};

template<class T>
struct ArgosLogHeader {

	typedef T							arch_spec;
	typedef typename T::address_t		address_t;
	typedef ArgosMemoryBlockHeader<T>	memory_block_t;

	static const int NUM_REGS	= T::NUM_REGS;
	static const int VERSION	= 2;

	uint8_t		format;
	uint8_t		arch;
	uint16_t	type;
	uint32_t	ts;
	address_t	reg[NUM_REGS];
	address_t	rtag[NUM_REGS];
	uint32_t	nettracker[NUM_REGS];	// optional net-tracker information
	address_t	eip;
	address_t	eiptag;
	uint32_t	eip_nettracker;			// optional net-tracker information
	address_t	old_eip;
	address_t	eflags;
};
#pragma pack(pop)

//------------------------------------------------------------------------------
// Name: outputHexString(T value)
//------------------------------------------------------------------------------
template<class T> 
std::string outputHexString(T value) {
	std::ostringstream ss;
	ss << "0x" << std::internal << std::hex << std::setw(sizeof(T) * 2) << std::setfill('0') << value;
	return ss.str();
}

//------------------------------------------------------------------------------
// Name: printBinary(void *binary, std::size_t n, std::size_t columnWidth, uint64_t vaddr = 0)
//------------------------------------------------------------------------------
void printBinary(void *binary, std::size_t n, std::size_t columnWidth, uint64_t vaddr = 0) {
	const uint8_t *p = static_cast<const uint8_t *>(binary);
	
	std::size_t i = 0;
	while(i < n) {
		
		// print the offset
		std::cout << std::hex << std::setw(8) << std::setfill('0') << (vaddr + i) << "  ";
		
		// print the data as bytes
		for(std::size_t j = 0; j < columnWidth;  ++j) {
			if((j + i) < n) {
				std::cout << std::hex << std::setw(2) << std::setfill('0') << (p[j + i] & 0xff) << ' ';
			} else {
				std::cout << "   ";
			}
		}
		std::cout << " |";
		
		// print the data as chars
		for(std::size_t j = 0; j < columnWidth;  ++j) {
			if((j + i) < n) {
				if(std::isprint(p[j + i]))	std::cout << p[j + i];
				else						std::cout << '.';
			}
		}		
		
		i += columnWidth;

		std::cout << "|\n";
	}
}

//------------------------------------------------------------------------------
// Name: tainedToString(T value)
//------------------------------------------------------------------------------
template<class T> 
std::string tainedToString(T value) {
	switch(value) {
	case 0:
		return "C ";
	case -1:
		return "TN";
	default:
		return "T ";
	}
}

//------------------------------------------------------------------------------
// Name: processMemoryBlocks(std::ifstream &file, const ArgosLogHeader<S> &header)
//------------------------------------------------------------------------------
template<class S>
int processMemoryBlocks(std::ifstream &file, const ArgosLogHeader<S> &header) {
	
	typename ArgosLogHeader<S>::memory_block_t blockHeader;
	
	while(file.read(reinterpret_cast<char *>(&blockHeader), sizeof(blockHeader))) {
		uint8_t *const data = new uint8_t[blockHeader.size];
		if(!file.read(reinterpret_cast<char *>(data), blockHeader.size)) {
			return -1;
		}
		
		if(blockHeader.size == 0) {
			break;
		}

		if((blockHeader.tainted != 0) || !g_print_only_tainted) {

			std::cout << "----------------------------------" << std::endl;
			std::cout << "MEMORY BLOCK HAS NET TRACKER DATA: " << std::boolalpha << ((blockHeader.format & 0x80) != 0) << std::endl;
			std::cout << "MEMORY BLOCK VERSION:              " << (blockHeader.format & 0x3f) << std::endl;
			
			assert((blockHeader.format & 0x3f) == blockHeader.VERSION);

			std::cout << "MEMORY BLOCK TAINTED:              " << std::boolalpha <<  (blockHeader.tainted != 0) << std::endl;
			std::cout << "MEMORY BLOCK SIZE:                 " << std::hex << blockHeader.size << std::endl;
			std::cout << "MEMORY BLOCK PADDR:                " << outputHexString(blockHeader.paddr) << std::endl;
			std::cout << "MEMORY BLOCK VADDR:                " << outputHexString(blockHeader.vaddr) << std::endl;
			
			if(header.eip >= blockHeader.vaddr && header.eip < blockHeader.vaddr + blockHeader.size) {
				std::cout << "POSSIBLE SHELLCODE BLOCK!" << std::endl;
			}

			printBinary(data, blockHeader.size, 16, blockHeader.vaddr);
		}

		delete [] data;
		
		// read in optional net-tracker information
		if((blockHeader.format & 0x80) != 0) {
			uint8_t *const data = new uint8_t[blockHeader.size * 4];
			
			if(!file.read(reinterpret_cast<char *>(data), blockHeader.size * 4)) {
				return -1;
			}
			
			// for now we don't process the net-tracker stuff
			delete [] data;
		}
	}
	return 0;
}

//------------------------------------------------------------------------------
// Name: processFile(std::ifstream &file, ArgosLogHeader<S> &header)
//------------------------------------------------------------------------------
template<class S>
int processFile(std::ifstream &file, ArgosLogHeader<S> &header) {

	typedef  ArgosLogHeader<S> header_t;
	
	// assert we are looking at a sane version of the file
	assert((header.format & 0x3f) <= header_t::VERSION);

	// read int he registers and there tags
	if(!file.read(reinterpret_cast<char *>(header.reg), sizeof(header.reg))) {
		return -1;
	}
	
	if(!file.read(reinterpret_cast<char *>(header.rtag), sizeof(header.rtag))) {
		return -1;
	}
	
	// read in the optional net-tracker information
	if((header.format & 0x80) != 0) {
		if(!file.read(reinterpret_cast<char *>(header.nettracker), sizeof(header.nettracker))) {
			return -1;
		}
	}
	
	// read in the EIP and it's tag
	if(!file.read(reinterpret_cast<char *>(&header.eip), sizeof(header.eip))) {
		return -1;
	}
	
	if(!file.read(reinterpret_cast<char *>(&header.eiptag), sizeof(header.eiptag))) {
		return -1;
	}

	// read in the optional net-tracker information
	if((header.format & 0x80) != 0) {
		if(!file.read(reinterpret_cast<char *>(&header.eip_nettracker), sizeof(header.eip_nettracker))) {
			return -1;
		}
	}

	// the old eip is only in version 2 or later
	if((header.format & 0x3f) > 1) {
		if(!file.read(reinterpret_cast<char *>(&header.old_eip), sizeof(header.old_eip))) {
			return -1;	
		}
	}
	
	// finally the eflags
	if(!file.read(reinterpret_cast<char *>(&header.eflags), sizeof(header.eflags))) {
		return -1;
	}

	std::cout << std::endl;
	for(int i = 0; i < header_t::NUM_REGS; ++i) {			
		std::cout << header_t::arch_spec::register_names[i] << " [" << outputHexString(header.reg[i]) << "] (" << tainedToString(header.rtag[i]) << ") ";
		if(((i + 1) % 4) == 0) {                                      
			std::cout << std::endl;
		}
	}

	std::cout << "eip    " << " [" << outputHexString(header.eip)     << "] (" << tainedToString(header.eiptag) << ") " << std::endl;
	std::cout << "old_eip" << " [" << outputHexString(header.old_eip) << "]" << std::endl;
	std::cout << "efl    " << " [" << outputHexString(header.eflags)  << "]" << std::endl;
	
	return processMemoryBlocks<S>(file, header);
}

//------------------------------------------------------------------------------
// Name: usage(const char *arg0)
//------------------------------------------------------------------------------
void usage(const char *arg0) {
	std::cerr << "usage: " << arg0 << " <filename> [options]" << std::endl;
	std::cerr << "OPTIONS:" << std::endl;
	std::cerr << "    --help         : display this help message" << std::endl;
	std::cerr << "    --tainted_only : only show tained memory blocks" << std::endl;
	std::cerr << "    --             : end of options" << std::endl;
	exit(-1);
}

//------------------------------------------------------------------------------
// Name: main(int argc, char *argv[])
//------------------------------------------------------------------------------
int main(int argc, char *argv[]) {
	
	if(argc < 2 || std::string(argv[1]) == "--help") {
		usage(argv[0]);
	} else {	
		for(int i = 2; i != argc; ++i) {
			if(std::string(argv[i]) == "--") {
				break;
			} else if(std::string(argv[i]) == "--tainted_only") {
				g_print_only_tainted = true;
			} else {
				usage(argv[0]);
			}
		}
	}
	
	std::ifstream file(argv[1], std::ios::in | std::ios::binary);
	if(file) {
	
		union {
			ArgosLogHeader<arch_spec_x86>		header_x86;
			ArgosLogHeader<arch_spec_x86_64>	header_x86_64;
		};
		
		// clear out the union, we only need to do the bigger of the two
		std::memset(&header_x86_64, 0, sizeof(header_x86_64));
		
		// read the common portion (the first 4 fields) to get the arch type
		// doesn't matter which version of the header we use here
		// as these portions occupy the same space
		if(!file.read(reinterpret_cast<char *>(&header_x86.format), sizeof(header_x86.format))) {
			return -1;
		}

		if(!file.read(reinterpret_cast<char *>(&header_x86.arch), sizeof(header_x86.arch))) {
			return -1;
		}
		
		if(!file.read(reinterpret_cast<char *>(&header_x86.type), sizeof(header_x86.type))) {
			return -1;
		}
		
		if(!file.read(reinterpret_cast<char *>(&header_x86.ts), sizeof(header_x86.ts))) {
			return -1;
		}


		std::cout << "NET TRACKER DATA: " << std::boolalpha << ((header_x86.format & 0x80) != 0) << std::endl;
		std::cout << "HOST ENDIAN:      " << (((header_x86.format & 0x40) != 0) ? "big-endian" : "little-endian") << std::endl;
		std::cout << "HEADER VERSION:   " << (header_x86.format & 0x3f) << std::endl;			
		const time_t attack_time = static_cast<time_t>(header_x86.ts);
		std::cout << "TIMESTAMP:        " << ctime(&attack_time);
		std::cout << "GUEST ARCH:       " << ((header_x86.arch == 1) ? "x86-64" : "x86") << std::endl;


		if(header_x86.type < (sizeof(argos_alert_names) / sizeof(argos_alert_names[0]))) {
			std::cout << "ALERT TYPE:       " << argos_alert_names[header_x86.type] << std::endl;
		} else {
			std::cout << "ALERT TYPE:       INVALID" << std::endl;
		}

		// process the file using the appropriate arch specs
		if(header_x86.arch == 1) {
			processFile<arch_spec_x86_64>(file, header_x86_64);
		} else {
			processFile<arch_spec_x86>(file, header_x86);
		}		

	}
}
