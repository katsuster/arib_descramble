#ifndef DESCRAMBLER_TS_HPP__
#define DESCRAMBLER_TS_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include <string>

#include "multi2.hpp"

class descrambler_ts {
public:
	descrambler_ts() :
		valid_odd(0), valid_even(0)
	{
	}

	virtual ~descrambler_ts()
	{
	}

	void set_system_key(uint8_t *k)
	{
		memcpy(system_key, k, SYSTEM_KEY_SIZE);
	}

	void invalid_data_key()
	{
		memset(data_key_odd, 0, DATA_KEY_SIZE);
		memset(data_key_even, 0, DATA_KEY_SIZE);
		valid_odd = 0;
		valid_even = 0;
	}

	int is_valid_odd() const
	{
		return valid_odd;
	}

	int is_valid_even() const
	{
		return valid_even;
	}

	void set_data_key_odd(uint64_t k)
	{
		uint8_t kb[DATA_KEY_SIZE];

		kb[0] = k >> 56;
		kb[1] = k >> 48;
		kb[2] = k >> 40;
		kb[3] = k >> 32;
		kb[4] = k >> 24;
		kb[5] = k >> 16;
		kb[6] = k >> 8;
		kb[7] = k >> 0;

		set_data_key(kb, NULL);
	}

	void set_data_key_even(uint64_t k)
	{
		uint8_t kb[DATA_KEY_SIZE];

		kb[0] = k >> 56;
		kb[1] = k >> 48;
		kb[2] = k >> 40;
		kb[3] = k >> 32;
		kb[4] = k >> 24;
		kb[5] = k >> 16;
		kb[6] = k >> 8;
		kb[7] = k >> 0;

		set_data_key(NULL, kb);
	}

	void set_data_key(uint8_t *k_odd, uint8_t *k_even)
	{
		if (k_odd) {
			memcpy(data_key_odd, k_odd, DATA_KEY_SIZE);
			valid_odd = 1;
		}

		if (k_even) {
			memcpy(data_key_even, k_even, DATA_KEY_SIZE);
			valid_even = 1;
		}
	}

	void set_init_vector(uint64_t v)
	{
		uint8_t vb[DATA_KEY_SIZE];

		vb[0] = v >> 56;
		vb[1] = v >> 48;
		vb[2] = v >> 40;
		vb[3] = v >> 32;
		vb[4] = v >> 24;
		vb[5] = v >> 16;
		vb[6] = v >> 8;
		vb[7] = v >> 0;

		set_init_vector(vb);
	}

	void set_init_vector(uint8_t *v)
	{
		memcpy(init_vector, v, DATA_BLK_SIZE);
	}

	int is_odd(packet_ts& ts)
	{
		if (!is_valid_odd())
			return 0;

		if (ts.transport_scrambling_control != 3)
			return 0;

		return 1;
	}

	int is_even(packet_ts& ts)
	{
		if (!is_valid_even())
			return 0;

		if (ts.transport_scrambling_control != 2)
			return 0;

		return 1;
	}

	void descramble(packet_ts& ts)
	{
		uint8_t work_reg[DATA_BLK_SIZE];
		uint8_t work_out[DATA_BLK_SIZE];
		uint8_t key[ALL_KEY_SIZE];
		size_t pos, len;

		if (is_odd(ts))
			memcpy(key, data_key_odd, DATA_KEY_SIZE);
		else if (is_even(ts))
			memcpy(key, data_key_even, DATA_KEY_SIZE);
		else
			//data key is not ready, cannot descramble
			return;

		memcpy(key + DATA_KEY_SIZE, system_key, SYSTEM_KEY_SIZE);

		dec.init(1, key, ALL_KEY_SIZE);
		enc.init(0, key, ALL_KEY_SIZE);

		memcpy(work_reg, init_vector, DATA_BLK_SIZE);

		pos = 0;
		len = ts.payload_len;

		//CBC mode
		while (len >= DATA_BLK_SIZE) {
			dec.update(ts.payload, pos, work_out, 0);

			for (int i = 0; i < DATA_BLK_SIZE; i++)
				work_out[i] ^= work_reg[i];

			memcpy(work_reg, &ts.payload[pos], DATA_BLK_SIZE);
			memcpy(&ts.payload[pos], work_out, DATA_BLK_SIZE);

			pos += DATA_BLK_SIZE;
			len -= DATA_BLK_SIZE;
		}

		//OFB mode
		while (len > 0) {
			enc.update(work_reg, 0, work_out, 0);

			for (int i = 0; len > 0; i++, pos++, len--)
				ts.payload[pos] ^= work_out[i];
		}

		ts.transport_scrambling_control = 0;
	}

private:
	int valid_odd;
	int valid_even;
	uint8_t system_key[SYSTEM_KEY_SIZE];
	uint8_t data_key_odd[DATA_KEY_SIZE];
	uint8_t data_key_even[DATA_KEY_SIZE];
	uint8_t init_vector[8];

	multi2 dec;
	multi2 enc;
};

#endif //DESCRAMBLER_TS_HPP__
