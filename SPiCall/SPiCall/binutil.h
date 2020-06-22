#pragma once
#include <iostream>
#include <array>

namespace BinUtil {
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
}
