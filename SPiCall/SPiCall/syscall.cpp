#include <iostream>
#include <vector>
#include <algorithm>
#include "syscall.h"
#include "Basic.h"
#include "PE.h"
#include "binutil.h"

size_t MapFreshNt()
{
	unsigned long status = -1;
	size_t hSection;
	char cntdll[] = { '\xef','N','\xfe','T','\xef','D','\xfe','L','\xef','L','\xfe','.','\xef','D','\xfe','L','\xef','L','\x00','\x00' };
	for (int i = 0; i <= 192; i += 4)
	{
		cntdll[(i * 2)%sizeof(cntdll)] ^= 3 * (char)i;
		wchar_t wntdll[sizeof(cntdll) / 2];
		for (int j = 0; j < sizeof(cntdll) / 2; j++)
		{
			wntdll[j] = cntdll[j * 2 + 1];
		}
		OBJECT_ATTRIBUTES attr{ .Length = sizeof(OBJECT_ATTRIBUTES),.Attributes = 64 };
		UNICODE_STRING pstr2{ sizeof(cntdll) - 2,sizeof(cntdll), wntdll};
		attr.ObjectName = &pstr2;
		attr.RootDirectory = i;
		status = NtOpenSection(&hSection, 15, &attr);
		if (!status)
			break;
	}

	if (status)
		return 0;

	size_t BaseAddress = 0;
	size_t ViewSize = 0;
	status = NtMapViewOfSection(hSection, -1,
		(void**)&BaseAddress, 0, 0, 0, &ViewSize, 1, 0, 0x20);

	NtClose(hSection);
	return BaseAddress;
}

template<typename U, typename V>
struct reviewer {
	constexpr bool operator()(const std::pair<U, V> a, const std::pair<U, V> b) const
	{
		return a.first < b.first;
	};
};

std::vector<std::pair<uint32_t,int>> syscallnomap;
bool SPiCall::init()
{
	syscallnomap.clear();
	using namespace SPiCall;
	using namespace SPiCall::PE;
	typedef struct _IMAGE_EXPORT_DIRECTORY {
		DWORD   Characteristics;
		DWORD   TimeDateStamp;
		WORD    MajorVersion;
		WORD    MinorVersion;
		DWORD   Name;
		DWORD   Base;
		DWORD   NumberOfFunctions;
		DWORD   NumberOfNames;
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	} IMAGE_EXPORT_DIRECTORY;

	auto ntdll = MapFreshNt();
	if (!ntdll)
		return false;

	PEViewer pe(ntdll);
	auto NTHeader = pe.getNtHeader();
	auto ExportDict = NTHeader->OptionalHeader.DataDirectory[0];
	auto edir = (IMAGE_EXPORT_DIRECTORY*)ExportDict.VirtualAddress.with(ntdll);

	auto FnNameView = (RVA32<char>*)RVA32<DWORD>(edir->AddressOfNames).with(ntdll);
	auto FnView = (RVA32< char >*)RVA32<DWORD>(edir->AddressOfFunctions).with(ntdll);

	std::vector<std::pair<WORD, uint32_t>> ordmap;
	for (int i = 0; i < (int)edir->NumberOfNames; i++)
	{
		const auto name = FnNameView[i].with(ntdll);
		auto OrdView = RVA32<WORD>(edir->AddressOfNameOrdinals + i * 2).with(ntdll);
		ordmap.push_back(std::make_pair(*OrdView, SPiCall::syscall::fnv1a_32(name)));
	}

	std::sort(ordmap.begin(), ordmap.end(), reviewer<WORD, uint32_t>());

	for (int i = 0; i < (int)edir->NumberOfFunctions; i++)
	{
		auto func = FnView[i].with(ntdll);
		const auto pat1 = BinUtil::pattern_to_ints("B8 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 75 03 0f 05");
		const char* moveax = BinUtil::findPattern((char*)func, 0x20, pat1);
		if (!moveax)
		{
			const auto pat2 = BinUtil::pattern_to_ints("B8 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 75 03 0f 05");
			moveax = BinUtil::findPattern((char*)func, 0x20, pat2);
		}

		if (moveax)
		{
			auto no = *(DWORD*)(moveax + 1);

			auto m = std::lower_bound(ordmap.begin(), ordmap.end(), std::pair<WORD, uint32_t>(i, 0), reviewer<WORD, uint32_t>());
			if (m != ordmap.end() && m->first == i)
			{
				syscallnomap.push_back(std::make_pair(m->second, no));
			}
		}
	}
	NtUnmapViewOfSection(-1, (void*)ntdll);

	std::sort(syscallnomap.begin(), syscallnomap.end(), reviewer<uint32_t, int>());
    return true;
}

int SPiCall::syscall::get_syscall_no(uint32_t namehash)
{
	auto m = std::lower_bound(syscallnomap.begin(), syscallnomap.end(), std::pair<uint32_t, int>(namehash, 0), reviewer<uint32_t, int>());
	if (m != syscallnomap.end() && m->first == namehash)
	{
		return m->second;
	}
	return 0;
}
