#pragma once
#include <iostream>
#include <array>

namespace BinUtil {
	inline constexpr int atoi(const char ch)
	{
		if (ch >= '0' && ch <= '9')
		{
			return ch - '0';
		}
		if (ch >= 'a' && ch <= 'z')
		{
			return ch - 'a' + 10;
		}
		if (ch >= 'A' && ch <= 'Z')
		{
			return ch - 'A' + 10;
		}
		return -1;
	}

	template<size_t N>
	inline constexpr std::array<short, N / 3> pattern_to_ints(const char(&pattern)[N]) {
		std::array<short, N / 3> result;
		for (int i = 0; i < N / 3; i++)
		{
			result[i] = atoi(pattern[i * 3 + 0]) * 16 +
				atoi(pattern[i * 3 + 1]);
		}
		return result;
	}

	template<size_t N>
	inline const char* findPattern(const char* buff, size_t len, std::array<short, N> ipat)
	{
		size_t i = 0;
		while (i < len - (N - 1))
		{
			int j = 0;
			for (; j < N; j++)
			{
				auto c = ipat[j];
				if (c >= 0)
				{
					if (buff[i + j] != (char)c) {
						break;
					}
				}
			}
			if (j == N)
			{
				return buff + i;
			}
			i++;
		}
		return 0;
	}

	template<size_t N>
	inline const char* findPattern(const char* buff, size_t len, const char(&pattern)[N])
	{
		return findPattern<N/3>(buff, len, pattern_to_ints(pattern));
	}
}
