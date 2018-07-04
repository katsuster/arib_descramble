#ifndef MULTI2_HPP__
#define MULTI2_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#define DATA_BLK_SIZE      8
#define DATA_KEY_SIZE      DATA_BLK_SIZE
#define SYSTEM_KEY_SIZE    32
#define ALL_KEY_SIZE       (DATA_KEY_SIZE + SYSTEM_KEY_SIZE)

class multi2 {
public:
	multi2() :
		round(32), decmode(1)
	{
	}

	int get_round() const
	{
		return round;
	}

	void set_round(int r)
	{
		round = r;
	}

	int get_decmode() const
	{
		return decmode;
	}

	void set_decmode(int en)
	{
		decmode = en;
	}

	const uint32_t *get_workkey() const
	{
		return workkey;
	}

	/**
	 * Initialize decrypt/encrypt data key (Dk) and system key (Sk)
	 *
	 * @dec Set non-zero to decrypt, set zero to encrypt.
	 * @key first 8bytes (64bits) is data key,
	 *      last 32bytes (256bits) is system key
	 * @key_len must be 40
	 */
	void init(int dec, uint8_t *key, size_t key_len)
	{
		uint32_t intermed0[9], intermed1[9];
		uint32_t work[2];

		if (key_len < ALL_KEY_SIZE) {
			printf("key_len too small, len:%d\n", (int)key_len);
			return;
		}

		decmode = dec;

		//read data key (64bits)
		//[0] left, [1] right
		read_key(key, 0, DATA_KEY_SIZE, work, 0);

		//read system key
		//[0] left, [7] right
		//  [0] k1-1 -> PI2 (first)
		//  [1] k1-2 -> PI3
		//  [2] k1-3 -> PI3
		//  [3] k1-4 -> PI4
		//  [4] k1-1 -> PI2 (second)
		//  [5] k1-2 -> PI3
		//  [6] k1-3 -> PI3
		//  [7] k1-4 -> PI4
		read_key(key, DATA_KEY_SIZE, SYSTEM_KEY_SIZE,
			workkey, 0);

		//create workkey
		mlt2_keyschedule(workkey, work, intermed0, intermed1);

		//set workkey
		workkey[0] = intermed0[1];
		workkey[1] = intermed1[2];
		workkey[2] = intermed0[3];
		workkey[3] = intermed1[4];
		workkey[4] = intermed0[5];
		workkey[5] = intermed1[6];
		workkey[6] = intermed0[7];
		workkey[7] = intermed1[8];
	}

	void update4(uint8_t *buf_in, uint8_t *buf_out)
	{
		for (int i = 0; i < 4; i++) {
			update(&buf_in[i * 8], 0, &buf_out[i * 8], 0);
		}
	}

	void update(uint8_t *buf_in, int offs_in, uint8_t *buf_out, size_t offs_out)
	{
		uint32_t *in = (uint32_t *)&buf_in[offs_in];
		uint32_t *out = (uint32_t *)&buf_out[offs_out];
		uint32_t tmp[2];

		tmp[0] = be32toh(in[0]);
		tmp[1] = be32toh(in[1]);

		if (decmode)
			decrypt_block(tmp);
		else
			encrypt_block(tmp);

		out[0] = htobe32(tmp[0]);
		out[1] = htobe32(tmp[1]);
	}

protected:
	void decrypt_block(uint32_t *blocks)
	{
		for (int i = 0; i < round; i += 8)
			mlt2_dec8round(get_workkey(), blocks);
	}

	void encrypt_block(uint32_t *blocks)
	{
		for (int i = 0; i < round; i += 8)
			mlt2_enc8round(get_workkey(), blocks);
	}

	void read_key(uint8_t *key, size_t key_offset, size_t key_len,
		uint32_t *work, size_t work_offset)
	{
		for (size_t i = 0, j = 0; i < key_len; i+= 4, j++) {
			work[work_offset + j] =
				(key[key_offset + i + 0] << 24) |
				(key[key_offset + i + 1] << 16) |
				(key[key_offset + i + 2] << 8) |
				(key[key_offset + i + 3] << 0);
		}
	}

	void mlt2_keyschedule(uint32_t *key, uint32_t *work, uint32_t *it0, uint32_t *it1)
	{
		uint32_t *partkey;

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi1(partkey, work);
		it0[0] = work[0];
		it1[0] = work[1];

		mlt2_pi2(partkey, work);
		it0[1] = work[0];
		it1[1] = work[1];

		mlt2_pi3(partkey, work);
		it0[2] = work[0];
		it1[2] = work[1];

		mlt2_pi4(partkey, work);
		it0[3] = work[0];
		it1[3] = work[1];

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi1(partkey, work);
		it0[4] = work[0];
		it1[4] = work[1];

		mlt2_pi2(partkey, work);
		it0[5] = work[0];
		it1[5] = work[1];

		mlt2_pi3(partkey, work);
		it0[6] = work[0];
		it1[6] = work[1];

		mlt2_pi4(partkey, work);
		it0[7] = work[0];
		it1[7] = work[1];

		mlt2_pi1(partkey, work);
		it0[8] = work[0];
		it1[8] = work[1];
	}

	void mlt2_dec8round(const uint32_t *key, uint32_t *work)
	{
		const uint32_t *partkey;

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi4(partkey, work);
		mlt2_pi3(partkey, work);
		mlt2_pi2(partkey, work);
		mlt2_pi1(partkey, work);

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi4(partkey, work);
		mlt2_pi3(partkey, work);
		mlt2_pi2(partkey, work);
		mlt2_pi1(partkey, work);
	}

	void mlt2_enc8round(const uint32_t *key, uint32_t *work)
	{
		const uint32_t *partkey;

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi1(partkey, work);
		mlt2_pi2(partkey, work);
		mlt2_pi3(partkey, work);
		mlt2_pi4(partkey, work);

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi1(partkey, work);
		mlt2_pi2(partkey, work);
		mlt2_pi3(partkey, work);
		mlt2_pi4(partkey, work);
	}

	void mlt2_pi1(const uint32_t *partkey, uint32_t *work)
	{
		uint32_t out[2];

		out[0] = work[0];
		out[1] = work[0] ^ work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi2(const uint32_t *partkey, uint32_t *work)
	{
		uint32_t out[2];
		uint32_t x, y, z;

		x = work[1];
		y = x + partkey[0];
		z = mlt2_rotl(y, 1) + y - 1;

		out[0] = work[0] ^ mlt2_rotl(z, 4) ^ z;
		out[1] = work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi3(const uint32_t *partkey, uint32_t *work)
	{
		uint32_t out[2];
		uint32_t x, y, z, a, b, c;

		x = work[0];
		y = x + partkey[1];
		z = mlt2_rotl(y, 2) + y + 1;
		a = mlt2_rotl(z, 8) ^ z;
		b = a + partkey[2];
		c = mlt2_rotl(b, 1) - b;

		out[0] = work[0];
		out[1] = work[1] ^ (mlt2_rotl(c, 16) ^ (c | x));

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi4(const uint32_t *partkey, uint32_t *work)
	{
		uint32_t out[2];
		uint32_t x, y;

		x = work[1];
		y = x + partkey[3];

		out[0] = work[0] ^ (mlt2_rotl(y, 2) + y + 1);
		out[1] = work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	uint32_t mlt2_rotl(uint32_t v, int n)
	{
		return (v << n) | ((v >> (32 - n)) & ((1 << n) - 1));
	}

private:
	int round;
	int decmode;
	uint32_t workkey[8];
};

#endif //MULTI2_HPP__
