#ifndef CARDRES_ECM_HPP__
#define CARDRES_ECM_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include "cardres.hpp"

class cardres_ecm : public cardres_base {
public:
	cardres_ecm() :
		ks_odd(0),
		ks_even(0),
		recording_control(0),
		sw1(0), sw2(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<cardres_ecm> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		cardres_base::read_stub(bs);
		if (is_error())
			return;

		ks_odd            = bs.get_bits(64);
		ks_even           = bs.get_bits(64);
		recording_control = bs.get_bits(8);
		sw1               = bs.get_bits(8);
		sw2               = bs.get_bits(8);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<cardres_ecm> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		cardres_base::dump();
		printf(FORMAT_STRING_LL
			FORMAT_STRING_LL
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"ks_odd"           , ks_odd           ,
			"ks_even"          , ks_even          ,
			"recording_control", recording_control,
			"sw1"              , sw1              ,
			"sw2"              , sw2              );
	}

public:
	uint64_t ks_odd;
	uint64_t ks_even;
	uint32_t recording_control;
	uint32_t sw1;
	uint32_t sw2;
};

#endif //CARDRES_ECM_HPP__
