#ifndef MULTI2_NEON_HPP__
#define MULTI2_NEON_HPP__

#if defined(__ARM_NEON)
#  include <arm_neon.h>
#endif

#include "multi2.hpp"

class multi2_neon : public multi2 {
public:
	multi2_neon()
	{
	}

#if defined(__ARM_NEON)
	void init(int dec, uint8_t *key, size_t key_len)
	{
		multi2::init(dec, key, key_len);

		for (int i = 0; i < 8; i++) {
			workkey_neon[i] = vdupq_n_u32(get_workkey()[i]);
		}
	}

	void update4(uint8_t *buf_in, uint8_t *buf_out)
	{
		uint32_t *in = (uint32_t *)buf_in;
		uint32_t *out = (uint32_t *)buf_out;
		uint32_t tmp[8];
		uint32x4_t tmp_b[2];

		for (int i = 0; i < 4; i++) {
			tmp[0 + i] = be32toh(in[i * 2 + 0]);
			tmp[4 + i] = be32toh(in[i * 2 + 1]);
		}

		tmp_b[0] = vld1q_u32(&tmp[0]);
		tmp_b[1] = vld1q_u32(&tmp[4]);

		if (get_decmode())
			decrypt_block_neon(tmp_b);
		else
			encrypt_block_neon(tmp_b);

		vst1q_u32(&tmp[0], tmp_b[0]);
		vst1q_u32(&tmp[4], tmp_b[1]);

		for (int i = 0; i < 4; i++) {
			out[i * 2 + 0] = htobe32(tmp[0 + i]);
			out[i * 2 + 1] = htobe32(tmp[4 + i]);
		}
	}

protected:
	void decrypt_block_neon(uint32x4_t *blocks)
	{
		for (int i = 0; i < get_round(); i += 8)
			mlt2_dec8round_neon(workkey_neon, blocks);
	}

	void encrypt_block_neon(uint32x4_t *blocks)
	{
		for (int i = 0; i < get_round(); i += 8)
			mlt2_enc8round_neon(workkey_neon, blocks);
	}

	void mlt2_dec8round_neon(const uint32x4_t *key, uint32x4_t *work)
	{
		const uint32x4_t *partkey;

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi4_neon(partkey, work);
		mlt2_pi3_neon(partkey, work);
		mlt2_pi2_neon(partkey, work);
		mlt2_pi1_neon(partkey, work);

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi4_neon(partkey, work);
		mlt2_pi3_neon(partkey, work);
		mlt2_pi2_neon(partkey, work);
		mlt2_pi1_neon(partkey, work);
	}

	void mlt2_enc8round_neon(const uint32x4_t *key, uint32x4_t *work)
	{
		const uint32x4_t *partkey;

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi1_neon(partkey, work);
		mlt2_pi2_neon(partkey, work);
		mlt2_pi3_neon(partkey, work);
		mlt2_pi4_neon(partkey, work);

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi1_neon(partkey, work);
		mlt2_pi2_neon(partkey, work);
		mlt2_pi3_neon(partkey, work);
		mlt2_pi4_neon(partkey, work);
	}

	void mlt2_pi1_neon(const uint32x4_t *partkey, uint32x4_t *work)
	{
		uint32x4_t out[2];

		out[0] = work[0];
		out[1] = veorq_u32(work[0], work[1]);

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi2_neon(const uint32x4_t *partkey, uint32x4_t *work)
	{
		uint32x4_t out[2];
		uint32x4_t x, y, z;

		x = work[1];
		y = vaddq_u32(x, partkey[0]);
		z = vaddq_u32(mlt2_rotl_neon(y, 1), y);
		z = vsubq_u32(z, vdupq_n_u32(1));

		out[0] = veorq_u32(work[0], mlt2_rotl_neon(z, 4));
		out[0] = veorq_u32(out[0], z);
		out[1] = work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi3_neon(const uint32x4_t *partkey, uint32x4_t *work)
	{
		uint32x4_t out[2];
		uint32x4_t x, y, z, a, b, c;

		x = work[0];
		y = vaddq_u32(x, partkey[1]);
		z = vaddq_u32(mlt2_rotl_neon(y, 2), y);
		z = vaddq_u32(z, vdupq_n_u32(1));
		a = veorq_u32(mlt2_rotl_neon(z, 8), z);
		b = vaddq_u32(a, partkey[2]);
		c = vsubq_u32(mlt2_rotl_neon(b, 1), b);

		out[0] = work[0];
		out[1] = veorq_u32(work[1], mlt2_rotl_neon(c, 16));
		out[1] = veorq_u32(out[1], vorrq_u32(c, x));

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi4_neon(const uint32x4_t *partkey, uint32x4_t *work)
	{
		uint32x4_t out[2];
		uint32x4_t x, y;

		x = work[1];
		y = vaddq_u32(x, partkey[3]);

		out[0] = vaddq_u32(mlt2_rotl_neon(y, 2), y);
		out[0] = vaddq_u32(out[0], vdupq_n_u32(1));
		out[0] = veorq_u32(out[0], work[0]);
		out[1] = work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	uint32x4_t mlt2_rotl_neon(uint32x4_t x, int n)
	{
		uint32x4_t mw0, mw1;

		mw0 = vshlq_n_u32(x, n);
		mw1 = vshrq_n_u32(x, 32 - n);
		return vorrq_u32(mw0, mw1);
        }

private:
	uint32x4_t workkey_neon[8];
#endif //defined(__ARM_NEON)
};

#endif //MULTI2_NEON_HPP__
