#ifndef PACKET_TS_HPP__
#define PACKET_TS_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include "packet.hpp"

class ts_adapt : public packet {
public:
	ts_adapt() :
		adaptation_field_length(0),
		discontinuity_indicator(0),
		random_access_indicator(0),
		elementary_stream_priority_indicator(0),
		pcr_flag(0),
		opcr_flag(0),
		splicing_point_flag(0),
		transport_private_data_flag(0),
		adaptation_field_extension_flag(0),
		transport_private_data_length(0),
		adaptation_field_extension_length(0),
		ltw_flag(0),
		piecewise_rate_flag(0),
		seamless_splice_flag(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<ts_adapt> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		int pos = bs.position(), sz_stuff;

		adaptation_field_length = bs.get_bits(8);
		if (adaptation_field_length == 0)
			return;
		if (adaptation_field_length > (size_t)bs.remain()) {
			this->set_error(EINVAL,
				"adaptation field too large, len:%d, remain:%d",
				(int)adaptation_field_length,
				(int)bs.remain());
			return;
		}

		discontinuity_indicator              = bs.get_bits(1);
		random_access_indicator              = bs.get_bits(1);
		elementary_stream_priority_indicator = bs.get_bits(1);
		pcr_flag                             = bs.get_bits(1);
		opcr_flag                            = bs.get_bits(1);
		splicing_point_flag                  = bs.get_bits(1);
		transport_private_data_flag          = bs.get_bits(1);
		adaptation_field_extension_flag      = bs.get_bits(1);

		if (pcr_flag == 1) {
			bs.skip_bits(48);
		}

		if (opcr_flag == 1) {
			bs.skip_bits(48);
		}

		if (splicing_point_flag == 1) {
			bs.skip_bits(8);
		}

		if (transport_private_data_flag == 1) {
			transport_private_data_length = bs.get_bits(8);
			bs.skip_bits(transport_private_data_length * 8);
		}

		if (adaptation_field_extension_flag == 1) {
			read_ext(bs);
		}

		sz_stuff = adaptation_field_length + 1 -
				(bs.position() - pos);
		if (sz_stuff > 0) {
			bs.skip_bits(sz_stuff * 8);
		}
	}

	template <class T>
	void read_ext(bitstream<T>& bs)
	{
		int pos = bs.position(), sz_stuff_ext;

		adaptation_field_extension_length = bs.get_bits(8);
		if (adaptation_field_extension_length == 0)
			return;
		if (adaptation_field_extension_length > (size_t)bs.remain()) {
			this->set_error(EINVAL,
				"adaptation ext field too large, len:%d, remain:%d",
				(int)adaptation_field_extension_length,
				(int)bs.remain());
			return;
		}

		ltw_flag             = bs.get_bits(1);
		piecewise_rate_flag  = bs.get_bits(1);
		seamless_splice_flag = bs.get_bits(1);
		bs.skip_bits(5);

		if (ltw_flag == 1) {
			bs.skip_bits(16);
		}

		if (piecewise_rate_flag == 1) {
			bs.skip_bits(24);
		}

		if (seamless_splice_flag == 1) {
			bs.skip_bits(40);
		}

		sz_stuff_ext = adaptation_field_extension_length + 1 -
				(bs.position() - pos);
		if (sz_stuff_ext > 0) {
			bs.skip_bits(sz_stuff_ext * 8);
		}
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<ts_adapt> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

public:
	uint32_t adaptation_field_length;
	uint32_t discontinuity_indicator;
	uint32_t random_access_indicator;
	uint32_t elementary_stream_priority_indicator;
	uint32_t pcr_flag;
	uint32_t opcr_flag;
	uint32_t splicing_point_flag;
	uint32_t transport_private_data_flag;
	uint32_t adaptation_field_extension_flag;
	uint32_t transport_private_data_length;

	uint32_t adaptation_field_extension_length;
	uint32_t ltw_flag;
	uint32_t piecewise_rate_flag;
	uint32_t seamless_splice_flag;
};

class packet_ts : public packet {
public:
	packet_ts() :
		sync_byte(0),
		transport_error_indicator(0),
		payload_unit_start_indicator(0),
		transport_priority(0),
		pid(0),
		transport_scrambling_control(0),
		adaptation_field_control(0),
		continuity_counter(0),
		adapt(),
		payload_len(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<packet_ts> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		int pos = bs.position();

		sync_byte                    = bs.get_bits(8);
		transport_error_indicator    = bs.get_bits(1);
		payload_unit_start_indicator = bs.get_bits(1);
		transport_priority           = bs.get_bits(1);
		pid                          = bs.get_bits(13);
		transport_scrambling_control = bs.get_bits(2);
		adaptation_field_control     = bs.get_bits(2);
		continuity_counter           = bs.get_bits(4);

		if (transport_error_indicator)
			return;

		if (adaptation_field_control == 2 || adaptation_field_control == 3) {
			adapt.read(bs);
			if (adapt.is_error()) {
				this->dup_error(adapt);
				return;
			}
		}

		payload_len = 188 - bs.position() - pos;
		if (payload_len < 0) {
			this->set_error(EINVAL,
				"payload is invalid, len:%d",
				(int)payload_len);
			return;
		}

		size_t st = bs.position();
		for (size_t i = 0; i < payload_len; i++) {
			payload[i] = bs.buffer()[st + i];
		}
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<packet_ts> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
		//int pos = bs.position();

		if (is_error())
			return;

		bs.set_bits( 8, sync_byte                   );
		bs.set_bits( 1, transport_error_indicator   );
		bs.set_bits( 1, payload_unit_start_indicator);
		bs.set_bits( 1, transport_priority          );
		bs.set_bits(13, pid                         );
		bs.set_bits( 2, transport_scrambling_control);
		bs.set_bits( 2, adaptation_field_control    );
		bs.set_bits( 4, continuity_counter          );

		if (adaptation_field_control == 2 || adaptation_field_control == 3)
			adapt.write(bs);

		uint32_t st = 188 - payload_len;
		for (size_t i = 0; i < payload_len; i++) {
			bs.buffer()[st + i] = payload[i];
		}
	}

	virtual void dump()
	{
		printf(FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"sync_byte"                   , sync_byte                   ,
			"transport_error_indicator"   , transport_error_indicator   ,
			"payload_unit_start_indicator", payload_unit_start_indicator,
			"transport_priority"          , transport_priority          ,
			"pid"                         , pid                         ,
			"transport_scrambling_control", transport_scrambling_control,
			"adaptation_field_control"    , adaptation_field_control    ,
			"continuity_counter"          , continuity_counter          ,
			"payload_len"                 , payload_len                 );
	}

public:
	uint32_t sync_byte;
	uint32_t transport_error_indicator;
	uint32_t payload_unit_start_indicator;
	uint32_t transport_priority;
	uint32_t pid;
	uint32_t transport_scrambling_control;
	uint32_t adaptation_field_control;
	uint32_t continuity_counter;
	ts_adapt adapt;

	uint32_t payload_len;
	uint8_t payload[188];
};

class payload_ts {
public:
	payload_ts() :
		first(0), target(0), valid(-1)
	{
	}

	virtual ~payload_ts()
	{
	}

	const packet_ts& get_first_ts() const
	{
		return first_ts[valid];
	}

	packet_ts& get_first_ts()
	{
		return first_ts[valid];
	}

	const std::vector<uint8_t>& get_payload() const
	{
		return buf[valid];
	}

	std::vector<uint8_t>& get_payload()
	{
		return buf[valid];
	}

	void reset()
	{
		first = 0;
		target = 0;
		valid = -1;
	}

	bool is_valid() const
	{
		return valid != -1;
	}

	void add_ts(packet_ts& ts)
	{
		if (ts.payload_unit_start_indicator) {
			if (!first) {
				first = 1;
			} else {
				valid = target;
				next_target();
			}

			first_ts[target] = ts;
			buf[target].clear();
		}

		buf[target].insert(buf[target].end(), &ts.payload[0],
			&ts.payload[ts.payload_len]);
	}

protected:
	void next_target()
	{
		target++;
		if (target >= 2)
			target = 0;
	}

public:
	packet_ts first_ts[2];
	std::vector<uint8_t> buf[2];

	int first;
	int target;
	int valid;
};

#endif //PACKET_TS_HPP__
