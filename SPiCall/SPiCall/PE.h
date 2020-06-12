#pragma once
#include <iostream>
#include <memory>
#include "pedef.h"

namespace SPiCall
{
	namespace PE
	{
		class PEViewer
		{
			size_t base;
		public:
			PEViewer(size_t _base)
			{
				base = _base;
			}

			size_t getBase()
			{
				return base;
			}

			IMAGE_NT_HEADERS* getNtHeader()
			{
				auto DOSHeader = RVA32<IMAGE_DOS_HEADER>(0).with(base);
				return DOSHeader->e_lfanew.with(base);
			}
		};
	}

}
