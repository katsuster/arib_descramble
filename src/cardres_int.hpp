#ifndef CARDRES_INT_HPP__
#define CARDRES_INT_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include <vector>

#include "cardres.hpp"

class cardres_int : public cardres_base {
public:
	cardres_int() :
		ca_system_id(0),
		card_id_1(0),
		card_type(0),
		message_partition_length(0),
		descrambler_cbc_initial_value(0),
		system_management_id_count(0),
		sw1(0), sw2(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<cardres_int> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		cardres_base::read_stub(bs);
		if (is_error())
			return;

		ca_system_id             = bs.get_bits(16);
		card_id_1                = bs.get_bits(48);
		card_type                = bs.get_bits(8);
		message_partition_length = bs.get_bits(8);

		for (size_t i = 0; i < 32; i++)
			descrambling_system_key[i] = bs.get_bits(8);

		descrambler_cbc_initial_value = bs.get_bits(64);

		system_management_id_count    = bs.get_bits(8);
		if (system_management_id_count < 0) {
			this->set_error(EINVAL,
				"system_management_id too small, cnt:%d",
				(int)system_management_id_count);
			return;
		}

		system_management_id.clear();
		for (size_t i = 0; i < system_management_id_count; i++) {
			uint32_t id = bs.get_bits(16);

			system_management_id.push_back(id);
		}

		sw1 = bs.get_bits(8);
		sw2 = bs.get_bits(8);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<cardres_int> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		cardres_base::dump();
		printf(FORMAT_STRING
			FORMAT_STRING_LL
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING_LL
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"ca_system_id"                 , ca_system_id                 ,
			"card_id_1"                    , card_id_1                    ,
			"card_type"                    , card_type                    ,
			"message_partition_length"     , message_partition_length     ,
			"descrambler_cbc_initial_value", descrambler_cbc_initial_value,
			"system_management_id_count"   , system_management_id_count   ,
			"sw1"                          , sw1                          ,
			"sw2"                          , sw2                          );
	}

public:
	uint32_t ca_system_id;
	uint64_t card_id_1;
	uint32_t card_type;
	uint32_t message_partition_length;
	uint8_t descrambling_system_key[32];
	uint64_t descrambler_cbc_initial_value;
	uint32_t system_management_id_count;
	std::vector<uint32_t> system_management_id;
	uint32_t sw1;
	uint32_t sw2;
};

#endif //CARDRES_INT_HPP__
