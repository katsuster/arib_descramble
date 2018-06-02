#ifndef PSI_HPP__
#define PSI_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include "packet.hpp"

class psi_base : public packet {
public:
	psi_base() :
		pointer_field(0),
		table_id(0),
		section_syntax_indicator(0),
		section_length(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<psi_base> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		pointer_field            = bs.get_bits(8);
		if (pointer_field > bs.remain()) {
			set_error(EINVAL,
				"pointer_field too large, len:%d, remain:%d",
				(int)pointer_field,
				(int)bs.remain());
			return;
		}
		bs.skip_bits(pointer_field * 8);

		table_id                 = bs.get_bits(8);
		section_syntax_indicator = bs.get_bits(1);
		bs.skip_bits(3);
		section_length           = bs.get_bits(12);
		if (section_length > bs.remain()) {
			set_error(EINVAL,
				"section too large, len:%d, remain:%d",
				(int)section_length,
				(int)bs.remain());
			return;
		}
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<psi_base> s;
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
			"pointer_field"           , pointer_field           ,
			"table_id"                , table_id                ,
			"section_syntax_indicator", section_syntax_indicator,
			"section_length"          , section_length          );
	}

public:
	uint32_t pointer_field;
	uint32_t table_id;
	uint32_t section_syntax_indicator;
	uint32_t section_length;
};

#endif //PSI_HPP__
