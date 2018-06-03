#ifndef CARDRES_HPP__
#define CARDRES_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include "packet.hpp"

class cardres_base : public packet {
public:
	cardres_base() :
		protocol_unit_number(0),
		unit_length(0),
		ic_card_instruction(0),
		return_code(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<cardres_base> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		protocol_unit_number = bs.get_bits(8);
		unit_length          = bs.get_bits(8);
		ic_card_instruction  = bs.get_bits(16);
		return_code          = bs.get_bits(16);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<cardres_base> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf(FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"protocol_unit_number", protocol_unit_number,
			"unit_length"         , unit_length         ,
			"ic_card_instruction" , ic_card_instruction ,
			"return_code"         , return_code         );
	}

public:
	uint32_t protocol_unit_number;
	uint32_t unit_length;
	uint32_t ic_card_instruction;
	uint32_t return_code;
};

#endif //CARDRES_HPP__
