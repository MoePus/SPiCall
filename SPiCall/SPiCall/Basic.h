#pragma once
#include <iostream>
#include <string>
#include <locale>
#include <algorithm>
#include <functional>

#pragma comment(lib, "ntdll.lib")

namespace SPiCall {
	using QWORD = unsigned __int64;
	using DWORD = unsigned long;
	using WORD = unsigned short;
	using BYTE = unsigned char;

	template<typename T>
	struct non_negative
	{
		static bool call(T handle) noexcept
		{
			return (long long)(handle) > 0;
		}
	};

	template<typename Fun> struct _RAII {
		Fun _fun;
		_RAII(_RAII&&) = default;
		_RAII(const _RAII&) = default;
		template<typename FunArg> _RAII(FunArg&& fun) : _fun(std::forward<Fun>(fun)) {}
		~_RAII() { _fun(); }
	};
	typedef _RAII<std::function<void(void)>> finally;
	template<typename Fun> _RAII<Fun> RAII(const Fun& fun) { return _RAII<Fun>(fun); }
	template<typename Fun> _RAII<Fun> RAII(Fun&& fun) { return _RAII<Fun>(std::move(fun)); }
}


extern "C"
{
	typedef union _LARGE_INTEGER {
		struct {
			unsigned long LowPart;
			long HighPart;
		} DUMMYSTRUCTNAME;
		struct {
			unsigned long LowPart;
			long HighPart;
		} u;
		long long QuadPart;
	} LARGE_INTEGER;

	typedef LARGE_INTEGER* PLARGE_INTEGER;

	typedef struct _UNICODE_STRING
	{
		unsigned short Length;
		unsigned short MaximumLength;
		wchar_t* Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef struct _OBJECT_ATTRIBUTES
	{
		unsigned long  Length;
		size_t RootDirectory;
		PUNICODE_STRING ObjectName;
		unsigned long  Attributes;
		void* SecurityDescriptor; // PSECURITY_DESCRIPTOR;
		void* SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
	} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

	unsigned long __stdcall NtMapViewOfSection(
		size_t SectionHandle,
		size_t ProcessHandle,
		void** BaseAddress,
		unsigned long* ZeroBits,
		size_t CommitSize,
		PLARGE_INTEGER SectionOffset,
		size_t* ViewSize,
		unsigned long InheritDisposition,
		unsigned long AllocationType,
		unsigned long Win32Protect);

	unsigned long __stdcall NtUnmapViewOfSection(
		size_t ProcessHandle,
		void* BaseAddress
	);

	unsigned long __stdcall NtOpenSection(
		size_t* SectionHandle,
		unsigned long      DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes
	);

	void __stdcall RtlInitUnicodeString(
		PUNICODE_STRING DestinationString,
		const wchar_t* SourceString
	);

	void __stdcall NtClose(
		size_t Handle
	);

	unsigned long GetThreadId(size_t Thread);

	#define MEM_EXTENDED_PARAMETER_TYPE_BITS 8

	enum MEM_EXTENDED_PARAMETER_TYPE {
		MemExtendedParameterInvalidType = 0,
		MemExtendedParameterAddressRequirements = 1,
		MemExtendedParameterNumaNode = 2,
		MemExtendedParameterPartitionHandle = 3,
		MemExtendedParameterMax = 4,
	};

	typedef struct MEM_EXTENDED_PARAMETER {
		struct {
			unsigned long long Type : MEM_EXTENDED_PARAMETER_TYPE_BITS;
			unsigned long long Reserved : 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS;
		} DUMMYSTRUCTNAME;
		union {
			unsigned long long ULong64;
			void*   Pointer;
			size_t  Size;
			size_t  Handle;
			unsigned long   ULong;
		} DUMMYUNIONNAME;
	} MEM_EXTENDED_PARAMETER, * PMEM_EXTENDED_PARAMETER;

	typedef struct _MEM_ADDRESS_REQUIREMENTS {
		void* LowestStartingAddress;
		void* HighestEndingAddress;
		size_t Alignment;
	} MEM_ADDRESS_REQUIREMENTS, * PMEM_ADDRESS_REQUIREMENTS;

	typedef struct _MEMORY_BASIC_INFORMATION {
		void*  BaseAddress;
		void* AllocationBase;
		unsigned long  AllocationProtect;
		size_t RegionSize;
		unsigned long  State;
		unsigned long  Protect;
		unsigned long  Type;
	} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

	typedef struct WIN32_MEMORY_REGION_INFORMATION {
		void*  AllocationBase;
		unsigned long  AllocationProtect;
		union {
			unsigned long Flags;
			struct {
				unsigned long Private : 1;
				unsigned long MappedDataFile : 1;
				unsigned long MappedImage : 1;
				unsigned long MappedPageFile : 1;
				unsigned long MappedPhysical : 1;
				unsigned long DirectMapped : 1;
				unsigned long Reserved : 26;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		size_t RegionSize;
		size_t CommitSize;
	} WIN32_MEMORY_REGION_INFORMATION;
	typedef struct _MEMORY_WORKING_SET_EX_BLOCK
	{
		union
		{
			struct
			{
				size_t Valid : 1;
				size_t ShareCount : 3;
				size_t Win32Protection : 11;
				size_t Shared : 1;
				size_t Node : 6;
				size_t Locked : 1;
				size_t LargePage : 1;
				size_t Priority : 3;
				size_t Reserved : 3;
				size_t SharedOriginal : 1;
				size_t Bad : 1;
				size_t Win32GraphicsProtection : 4; // 19H1
#ifdef _WIN64
				size_t ReservedUlong : 28;
#endif
			};
			struct
			{
				size_t Valid : 1;
				size_t Reserved0 : 14;
				size_t Shared : 1;
				size_t Reserved1 : 5;
				size_t PageTable : 1;
				size_t Location : 2;
				size_t Priority : 3;
				size_t ModifiedList : 1;
				size_t Reserved2 : 2;
				size_t SharedOriginal : 1;
				size_t Bad : 1;
#ifdef _WIN64
				size_t ReservedUlong : 32;
#endif
			} Invalid;
		};
	} MEMORY_WORKING_SET_EX_BLOCK, * PMEMORY_WORKING_SET_EX_BLOCK;

	// private
	typedef struct _MEMORY_WORKING_SET_EX_INFORMATION
	{
		void* VirtualAddress;
		union
		{
			MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
			size_t Long;
		} u1;
	} MEMORY_WORKING_SET_EX_INFORMATION, * PMEMORY_WORKING_SET_EX_INFORMATION;



	size_t GetModuleHandleA(const char* mod);
	size_t GetProcAddress(size_t hModule, const char* lpProcName);
}