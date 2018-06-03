#ifndef DESC_CA_HPP__
#define DESC_CA_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include "desc.hpp"

class desc_ca : public desc_base {
public:
	desc_ca() :
		ca_system_id(0),
		ca_pid(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<desc_ca> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		desc_base::read_stub(bs);
		if (is_error())
			return;

		ca_system_id = bs.get_bits(16);
		bs.skip_bits(3);
		ca_pid       = bs.get_bits(13);

		//-4: size of descriptor_length .. ca_pid
		int n = descriptor_length - 4;
		if (n < 0) {
			set_error(EINVAL,
				"CA desc too small, len:%d", n);
			return;
		}
		bs.skip_bits(n * 8);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<desc_ca> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		desc_base::dump();
		printf(FORMAT_STRING
			FORMAT_STRING,
			"ca_system_id", ca_system_id,
			"ca_pid"      , ca_pid      );
	}

public:
	uint32_t ca_system_id;
	uint32_t ca_pid;
};

#endif //DESC_HPP__
