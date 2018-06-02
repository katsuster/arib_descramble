#ifndef PSI_PAT_HPP__
#define PSI_PAT_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include <vector>

#include "psi.hpp"

class pat_program : public packet {
public:
	pat_program() :
		program_number(0),
		network_pid(0),
		program_map_id(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<pat_program> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		program_number = bs.get_bits(16);
		bs.skip_bits(3);

		if (program_number == 0)
			network_pid    = bs.get_bits(13);
		else
			program_map_id = bs.get_bits(13);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<pat_program> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf("  " FORMAT_STRING
			"  " FORMAT_STRING
			"  " FORMAT_STRING,
			"program_number", program_number,
			"network_pid"   , network_pid   ,
			"program_map_id", program_map_id);
	}

public:
	uint32_t program_number;
	uint32_t network_pid;
	uint32_t program_map_id;
};

class psi_pat : public psi_base {
public:
	psi_pat() :
		transport_stream_id(0),
		version_number(-1),
		current_next_indicator(0),
		section_number(0),
		last_section_number(0),
		crc_32(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<psi_pat> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		psi_base::read_stub(bs);
		if (is_error())
			return;

		transport_stream_id    = bs.get_bits(16);
		bs.skip_bits(2);
		version_number         = bs.get_bits(5);
		current_next_indicator = bs.get_bits(1);
		section_number         = bs.get_bits(8);
		last_section_number    = bs.get_bits(8);

		//-5: size of section_length .. last_section_number
		//-4: size of crc32
		int n = (section_length - 5 - 4) / 4;
		if (n < 0) {
			set_error(EINVAL,
				"PAT program too small, len:%d", n);
			return;
		}

		progs.clear();
		for (int i = 0; i < n; i++) {
			pat_program pr;

			pr.read(bs);
			progs.push_back(pr);
		}

		crc_32 = bs.get_bits(32);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<psi_pat> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf("PAT -----\n");

		psi_base::dump();
		printf(FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"transport_stream_id"   , transport_stream_id   ,
			"version_number"        , version_number        ,
			"current_next_indicator", current_next_indicator,
			"section_number"        , section_number        ,
			"last_section_number"   , last_section_number   ,
			"crc_32"                , crc_32                );

		for (size_t i = 0; i < progs.size(); i++) {
			printf("    program[%d]\n", (int)i);
			progs[i].dump();
		}
	}

public:
	uint32_t transport_stream_id;
	uint32_t version_number;
	uint32_t current_next_indicator;
	uint32_t section_number;
	uint32_t last_section_number;
	uint32_t crc_32;

	std::vector<pat_program> progs;
};

#endif //PSI_PAT_HPP__
