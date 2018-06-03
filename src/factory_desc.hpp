#ifndef DESC_FACTORY_HPP__
#define DESC_FACTORY_HPP__

#include "desc.hpp"
#include "desc_ca.hpp"

class factory_desc {
public:
	factory_desc()
	{
	}

	static desc_base *create_desc(uint32_t tag)
	{
		switch (tag) {
		case DESC_CA:
			return new desc_ca;
		default:
			return new desc_unknown;
		}
	}

};

#endif //DESC_FACTORY_HPP__
