#pragma once
#include <iostream>

extern "C" void* asm_syscall();

namespace SPiCall {
	bool init(); // not thread safe

	namespace syscall {
		inline constexpr uint32_t fnv1a_32(const char* str, uint32_t hash = 2166136261)
		{
			while (*str)
			{
				hash = (*(char*)str++ ^ hash) * 16777619;
			}
			return hash;
		}

		int get_syscall_no(uint32_t namehash); // thread safe

		template<size_t N>
		inline constexpr int get_syscall_no(const char(&name)[N]) {
			auto hash = fnv1a_32(name);
			return get_syscall_no(hash);
		};

		template<typename... Args>
		inline unsigned long syscall(int sysno, Args... args)
		{
			//Alter: inline asm here to make syscall inline
			using FnType = unsigned long(*)(int, size_t, uint64_t...);
			return FnType(asm_syscall)(sysno, sizeof...(Args), uint64_t(args)...);
		}

		template<size_t N, typename... Args>
		inline unsigned long nt_syscall(const char(&name)[N], Args&& ... args)
		{
			return syscall(get_syscall_no(name), std::forward<Args>(args)...);
		}

		template<typename... Args>
		inline unsigned long nt_syscall(uint32_t namehash, Args&& ... args)
		{
			return syscall(get_syscall_no(namehash), std::forward<Args>(args)...);
		}
	}
}
