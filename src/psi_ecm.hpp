#ifndef PSI_ECM_HPP__
#define PSI_ECM_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include <string>
#include <vector>

#include "psi.hpp"

class psi_ecm : public psi_base {
public:
	psi_ecm() :
		table_id_extension(0),
		version_number(-1),
		current_next_indicator(0),
		section_number(0),
		last_section_number(0),
		crc_32(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<psi_ecm> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		//uint32_t e;

		psi_base::read_stub(bs);
		if (is_error())
			return;

		table_id_extension     = bs.get_bits(16);
		bs.skip_bits(2);
		version_number         = bs.get_bits(5);
		current_next_indicator = bs.get_bits(1);
		section_number         = bs.get_bits(8);
		last_section_number    = bs.get_bits(8);

		//-5: size of section_length .. last_section_number
		//-4: size of crc32
		int n = section_length - 5 - 4;
		if (n < 0) {
			set_error(EINVAL,
				"ECM body too small, len:%d", n);
			return;
		}

		body.clear();
		for (int i = 0; i < n; i++)
			body.push_back(bs.get_bits(8));

		crc_32 = bs.get_bits(32);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<psi_ecm> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf("ECM -----\n");

		psi_base::dump();
		printf(FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"table_id_extension"    , table_id_extension    ,
			"version_number"        , version_number        ,
			"current_next_indicator", current_next_indicator,
			"section_number"        , section_number        ,
			"last_section_number"   , last_section_number   ,
			"crc_32"                , crc_32                );

		std::string s;
		char l[80];

		for (size_t i = 0; i < body.size(); i++) {
			snprintf(l, sizeof(l), "%02x ", body[i]);
			s += l;
			if (i != 0 && (i % 16) == 15)
				s += "\n    ";
			else if (i != 0 && (i % 8) == 7)
				s += "- ";
		}
		printf("body:\n    %s\n", s.c_str());
	}

public:
	uint32_t table_id_extension;
	uint32_t version_number;
	uint32_t current_next_indicator;
	uint32_t section_number;
	uint32_t last_section_number;
	uint32_t crc_32;

	std::vector<uint8_t> body;
};

#endif //PSI_ECM_HPP__
