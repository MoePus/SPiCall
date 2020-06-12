#pragma once
#include <iostream>
#include <optional>
#include "Basic.h"

namespace SPiCall
{
	namespace PE
	{
		constexpr int __IMAGE_SIZEOF_SHORT_NAME = 8;
		constexpr int __IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

		template <typename T>
		class RVA32
		{
		public:
			DWORD rva;
			RVA32(DWORD _rva) :rva(_rva) {};

			T* with(size_t base)
			{
				return (T*)(base + rva);
			};
		};

		struct IMAGE_NT_HEADERS;
		struct IMAGE_DOS_HEADER {
			WORD   e_magic;                     // Magic number
			WORD   e_cblp;                      // Bytes on last page of file
			WORD   e_cp;                        // Pages in file
			WORD   e_crlc;                      // Relocations
			WORD   e_cparhdr;                   // Size of header in paragraphs
			WORD   e_minalloc;                  // Minimum extra paragraphs needed
			WORD   e_maxalloc;                  // Maximum extra paragraphs needed
			WORD   e_ss;                        // Initial (relative) SS value
			WORD   e_sp;                        // Initial SP value
			WORD   e_csum;                      // Checksum
			WORD   e_ip;                        // Initial IP value
			WORD   e_cs;                        // Initial (relative) CS value
			WORD   e_lfarlc;                    // File address of relocation table
			WORD   e_ovno;                      // Overlay number
			WORD   e_res[4];                    // Reserved words
			WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
			WORD   e_oeminfo;                   // OEM information; e_oemid specific
			WORD   e_res2[10];                  // Reserved words
			RVA32<IMAGE_NT_HEADERS>   e_lfanew; // File address of new exe header
		};

		struct IMAGE_FILE_HEADER {
			WORD    Machine;
			WORD    NumberOfSections;
			DWORD   TimeDateStamp;
			DWORD   PointerToSymbolTable;
			DWORD   NumberOfSymbols;
			WORD    SizeOfOptionalHeader;
			WORD    Characteristics;
		};


		struct PE_DIRECTORY {};
		struct IMAGE_DATA_DIRECTORY {
			RVA32<PE_DIRECTORY>		VirtualAddress;
			DWORD					Size;
		};

		struct IMAGE_OPTIONAL_HEADER64 {
			WORD        Magic;
			BYTE        MajorLinkerVersion;
			BYTE        MinorLinkerVersion;
			DWORD       SizeOfCode;
			DWORD       SizeOfInitializedData;
			DWORD       SizeOfUninitializedData;
			DWORD       AddressOfEntryPoint;
			DWORD       BaseOfCode;
			QWORD		ImageBase;
			DWORD       SectionAlignment;
			DWORD       FileAlignment;
			WORD        MajorOperatingSystemVersion;
			WORD        MinorOperatingSystemVersion;
			WORD        MajorImageVersion;
			WORD        MinorImageVersion;
			WORD        MajorSubsystemVersion;
			WORD        MinorSubsystemVersion;
			DWORD       Win32VersionValue;
			DWORD       SizeOfImage;
			DWORD       SizeOfHeaders;
			DWORD       CheckSum;
			WORD        Subsystem;
			WORD        DllCharacteristics;
			QWORD		SizeOfStackReserve;
			QWORD		SizeOfStackCommit;
			QWORD		SizeOfHeapReserve;
			QWORD		SizeOfHeapCommit;
			DWORD       LoaderFlags;
			DWORD       NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[__IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		};

		struct IMAGE_OPTIONAL_HEADER32 {
			WORD        Magic;
			BYTE        MajorLinkerVersion;
			BYTE        MinorLinkerVersion;
			DWORD       SizeOfCode;
			DWORD       SizeOfInitializedData;
			DWORD       SizeOfUninitializedData;
			DWORD       AddressOfEntryPoint;
			DWORD       BaseOfCode;
			DWORD       BaseOfData;
			DWORD		ImageBase;
			DWORD       SectionAlignment;
			DWORD       FileAlignment;
			WORD        MajorOperatingSystemVersion;
			WORD        MinorOperatingSystemVersion;
			WORD        MajorImageVersion;
			WORD        MinorImageVersion;
			WORD        MajorSubsystemVersion;
			WORD        MinorSubsystemVersion;
			DWORD       Win32VersionValue;
			DWORD       SizeOfImage;
			DWORD       SizeOfHeaders;
			DWORD       CheckSum;
			WORD        Subsystem;
			WORD        DllCharacteristics;
			DWORD		SizeOfStackReserve;
			DWORD		SizeOfStackCommit;
			DWORD		SizeOfHeapReserve;
			DWORD		SizeOfHeapCommit;
			DWORD       LoaderFlags;
			DWORD       NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[__IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		};
#ifdef _WIN64
		using IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64;
#else
		using IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER32;
#endif

		struct IMAGE_NT_HEADERS {
			DWORD Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER OptionalHeader;
		};

		struct DEBUG_INFO;
		struct DEBUG_DIRECTORY :PE_DIRECTORY
		{
			BYTE		PADDING[0x14];
			RVA32<DEBUG_INFO>	info;
		};

		struct DEBUG_INFO
		{
#pragma pack(push,1)
			DWORD		magic;
			DWORD		id_0_4_r;
			WORD		id_4_6_r;
			WORD		id_6_8_r;
			QWORD		id_8_16;
			BYTE		id_17_null3[4];
			char		PDBInfo[1];
#pragma pack(pop)

			std::optional<std::pair<std::string, std::string>> exp()
			{
				char buff[261] = { 0 };
				memcpy(buff, PDBInfo, 260);
				std::string pdbInfo = buff;

				auto fChToHex = [](BYTE* begin, int length, bool BE = false)->std::string
				{
					static const char* digits = "0123456789ABCDEF";
					std::string rc(length << 1, '0');

					BYTE* start = BE ? begin : begin + length - 1;
					BYTE* end = !BE ? begin - 1 : begin + length;
					int delta = BE ? 1 : -1;
					int index = 0;
					for (auto i = start; i != end; i += delta)
					{
						rc[index++] = digits[((*i) >> 4) & 0xf];
						rc[index++] = digits[(*i) & 0xf];
					}
					return rc;
				};
				std::string dbgId = fChToHex((BYTE*)&id_0_4_r, 4);
				dbgId += fChToHex((BYTE*)&id_4_6_r, 2);
				dbgId += fChToHex((BYTE*)&id_6_8_r, 2);
				dbgId += fChToHex((BYTE*)&id_8_16, 8, true);
				dbgId += fChToHex(id_17_null3, 1, true).substr(1);

				return std::make_pair(dbgId, pdbInfo);
			}
		};

		struct IMAGE_SECTION_HEADER {
			BYTE    Name[__IMAGE_SIZEOF_SHORT_NAME];
			union {
				DWORD   PhysicalAddress;
				DWORD   VirtualSize;
			} Misc;
			RVA32<BYTE>   VirtualAddress;
			DWORD   SizeOfRawData;
			DWORD   PointerToRawData;
			DWORD   PointerToRelocations;
			DWORD   PointerToLinenumbers;
			WORD    NumberOfRelocations;
			WORD    NumberOfLinenumbers;
			DWORD   Characteristics;
		};
	}
}
