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
		if (key_len < ALL_KEY_SIZE) {
			printf("key_len too small, len:%d\n", (int)key_len);
			return;
		}

		decmode = dec;

		//read data key (64bits)
		//[0] left, [1] right
		read_key(key, 0, DATA_KEY_SIZE, cipher, 0);

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
		mlt2_keyschedule();

		//set workkey
		workkey[0] = intermed[1][0];
		workkey[1] = intermed[2][1];
		workkey[2] = intermed[3][0];
		workkey[3] = intermed[4][1];
		workkey[4] = intermed[5][0];
		workkey[5] = intermed[6][1];
		workkey[6] = intermed[7][0];
		workkey[7] = intermed[8][1];
	}

	void update(uint8_t *buf_in, int offs_in, uint8_t *buf_out, size_t offs_out)
	{
		uint32_t tmp[2];

		tmp[0] = (buf_in[offs_in + 0] << 24) |
			 (buf_in[offs_in + 1] << 16) |
			 (buf_in[offs_in + 2] << 8) |
			 (buf_in[offs_in + 3] << 0);
		tmp[1] = (buf_in[offs_in + 4] << 24) |
			 (buf_in[offs_in + 5] << 16) |
			 (buf_in[offs_in + 6] << 8) |
			 (buf_in[offs_in + 7] << 0);

		if (decmode)
			decrypt_block(tmp);
		else
			encrypt_block(tmp);

		buf_out[offs_out + 0] = tmp[0] >> 24;
		buf_out[offs_out + 1] = tmp[0] >> 16;
		buf_out[offs_out + 2] = tmp[0] >> 8;
		buf_out[offs_out + 3] = tmp[0] >> 0;
		buf_out[offs_out + 4] = tmp[1] >> 24;
		buf_out[offs_out + 5] = tmp[1] >> 16;
		buf_out[offs_out + 6] = tmp[1] >> 8;
		buf_out[offs_out + 7] = tmp[1] >> 0;
	}

protected:
	void decrypt_block(uint32_t blocks[])
	{
		cipher[0] = blocks[0];
		cipher[1] = blocks[1];

		for (int i = 0; i < round; i += 8)
			mlt2_dec8round();

		blocks[0] = cipher[0];
		blocks[1] = cipher[1];
	}

	void encrypt_block(uint32_t blocks[])
	{
		cipher[0] = blocks[0];
		cipher[1] = blocks[1];

		for (int i = 0; i < round; i += 8)
			mlt2_enc8round();

		blocks[0] = cipher[0];
		blocks[1] = cipher[1];
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

	void mlt2_keyschedule()
	{
		//round 1 to 4
		partkey[0] = workkey[0];
		partkey[1] = workkey[1];
		partkey[2] = workkey[2];
		partkey[3] = workkey[3];

		mlt2_pi1();
		intermed[0][0] = cipher[0];
		intermed[0][1] = cipher[1];

		mlt2_pi2();
		intermed[1][0] = cipher[0];
		intermed[1][1] = cipher[1];

		mlt2_pi3();
		intermed[2][0] = cipher[0];
		intermed[2][1] = cipher[1];

		mlt2_pi4();
		intermed[3][0] = cipher[0];
		intermed[3][1] = cipher[1];

		//round 5 to 8
		partkey[0] = workkey[4];
		partkey[1] = workkey[5];
		partkey[2] = workkey[6];
		partkey[3] = workkey[7];

		mlt2_pi1();
		intermed[4][0] = cipher[0];
		intermed[4][1] = cipher[1];

		mlt2_pi2();
		intermed[5][0] = cipher[0];
		intermed[5][1] = cipher[1];

		mlt2_pi3();
		intermed[6][0] = cipher[0];
		intermed[6][1] = cipher[1];

		mlt2_pi4();
		intermed[7][0] = cipher[0];
		intermed[7][1] = cipher[1];

		mlt2_pi1();
		intermed[8][0] = cipher[0];
		intermed[8][1] = cipher[1];
	}

	void mlt2_dec8round()
	{
		//round 5 to 8
		partkey[0] = workkey[4];
		partkey[1] = workkey[5];
		partkey[2] = workkey[6];
		partkey[3] = workkey[7];

		mlt2_pi4();
		mlt2_pi3();
		mlt2_pi2();
		mlt2_pi1();

		//round 1 to 4
		partkey[0] = workkey[0];
		partkey[1] = workkey[1];
		partkey[2] = workkey[2];
		partkey[3] = workkey[3];

		mlt2_pi4();
		mlt2_pi3();
		mlt2_pi2();
		mlt2_pi1();
	}

	void mlt2_enc8round()
	{
		//round 1 to 4
		partkey[0] = workkey[0];
		partkey[1] = workkey[1];
		partkey[2] = workkey[2];
		partkey[3] = workkey[3];

		mlt2_pi1();
		mlt2_pi2();
		mlt2_pi3();
		mlt2_pi4();

		//round 5 to 8
		partkey[0] = workkey[4];
		partkey[1] = workkey[5];
		partkey[2] = workkey[6];
		partkey[3] = workkey[7];

		mlt2_pi1();
		mlt2_pi2();
		mlt2_pi3();
		mlt2_pi4();
	}

	void mlt2_pi1()
	{
		uint32_t out[2];

		out[0] = cipher[0];
		out[1] = cipher[0] ^ cipher[1];

		cipher[0] = out[0];
		cipher[1] = out[1];
	}

	void mlt2_pi2()
	{
		uint32_t out[2];
		uint32_t x, y, z;

		x = cipher[1];
		y = x + partkey[0];
		z = mlt2_rotl(y, 1) + y - 1;

		out[0] = cipher[0] ^ (mlt2_rotl(z, 4) ^ z);
		out[1] = cipher[1];

		cipher[0] = out[0];
		cipher[1] = out[1];
	}

	void mlt2_pi3()
	{
		uint32_t out[2];
		uint32_t x, y, z, a, b, c;

		x = cipher[0];
		y = x + partkey[1];
		z = mlt2_rotl(y, 2) + y + 1;
		a = mlt2_rotl(z, 8) ^ z;
		b = a + partkey[2];
		c = mlt2_rotl(b, 1) - b;

		out[0] = cipher[0];
		out[1] = cipher[1] ^ (mlt2_rotl(c, 16) ^ (c | x));

		cipher[0] = out[0];
		cipher[1] = out[1];
	}

	void mlt2_pi4()
	{
		uint32_t out[2];
		uint32_t x, y;

		x = cipher[1];
		y = x + partkey[3];

		out[0] = cipher[0] ^ (mlt2_rotl(y, 2) + y + 1);
		out[1] = cipher[1];

		cipher[0] = out[0];
		cipher[1] = out[1];
	}

	uint32_t mlt2_rotl(uint32_t v, int n)
	{
		return (v << n) | ((v >> (32 - n)) & ((1 << n) - 1));
	}

private:
	int round;
	int decmode;
	uint32_t cipher[2];
	uint32_t intermed[9][2];
	uint32_t workkey[8];
	uint32_t partkey[4];
};

#endif //MULTI2_HPP__
