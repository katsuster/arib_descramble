#ifndef MULTI2_SSE2_HPP__
#define MULTI2_SSE2_HPP__

#if defined(__SSE2__)
#  include <emmintrin.h>
#endif

#include "multi2.hpp"

class multi2_sse2 : public multi2 {
public:
	multi2_sse2()
	{
	}

#if defined(__SSE2__)
	void init(int dec, uint8_t *key, size_t key_len)
	{
		multi2::init(dec, key, key_len);

		for (int i = 0; i < 8; i++) {
			workkey_sse2[i] = _mm_set1_epi32(get_workkey()[i]);
		}
	}

	void update4(uint8_t *buf_in, int offs_in, uint8_t *buf_out, size_t offs_out)
	{
		uint32_t *in = (uint32_t *)&buf_in[offs_in];
		uint32_t *out = (uint32_t *)&buf_out[offs_out];
		uint32_t tmp[8];
		__m128i tmp_b[2];

		for (int i = 0; i < 4; i++) {
			tmp[0 + i] = be32toh(in[i * 2 + 0]);
			tmp[4 + i] = be32toh(in[i * 2 + 1]);
		}

		tmp_b[0] = _mm_load_si128((__m128i *)&tmp[0]);
		tmp_b[1] = _mm_load_si128((__m128i *)&tmp[4]);

		if (get_decmode())
			decrypt_block_sse2(tmp_b);
		else
			encrypt_block_sse2(tmp_b);

		_mm_store_si128((__m128i *)&tmp[0], tmp_b[0]);
		_mm_store_si128((__m128i *)&tmp[4], tmp_b[1]);

		for (int i = 0; i < 4; i++) {
			out[i * 2 + 0] = htobe32(tmp[0 + i]);
			out[i * 2 + 1] = htobe32(tmp[4 + i]);
		}
	}

protected:
	void decrypt_block_sse2(__m128i *blocks)
	{
		for (int i = 0; i < get_round(); i += 8)
			mlt2_dec8round_sse2(workkey_sse2, blocks);
	}

	void encrypt_block_sse2(__m128i *blocks)
	{
		for (int i = 0; i < get_round(); i += 8)
			mlt2_enc8round_sse2(workkey_sse2, blocks);
	}

	void mlt2_dec8round_sse2(const __m128i *key, __m128i *work)
	{
		const __m128i *partkey;

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi4_sse2(partkey, work);
		mlt2_pi3_sse2(partkey, work);
		mlt2_pi2_sse2(partkey, work);
		mlt2_pi1_sse2(partkey, work);

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi4_sse2(partkey, work);
		mlt2_pi3_sse2(partkey, work);
		mlt2_pi2_sse2(partkey, work);
		mlt2_pi1_sse2(partkey, work);
	}

	void mlt2_enc8round_sse2(const __m128i *key, __m128i *work)
	{
		const __m128i *partkey;

		//round 1 to 4
		partkey = &key[0];

		mlt2_pi1_sse2(partkey, work);
		mlt2_pi2_sse2(partkey, work);
		mlt2_pi3_sse2(partkey, work);
		mlt2_pi4_sse2(partkey, work);

		//round 5 to 8
		partkey = &key[4];

		mlt2_pi1_sse2(partkey, work);
		mlt2_pi2_sse2(partkey, work);
		mlt2_pi3_sse2(partkey, work);
		mlt2_pi4_sse2(partkey, work);
	}

	void mlt2_pi1_sse2(const __m128i *partkey, __m128i *work)
	{
		__m128i out[2];

		out[0] = work[0];
		out[1] = _mm_xor_si128(work[0], work[1]);

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi2_sse2(const __m128i *partkey, __m128i *work)
	{
		__m128i out[2];
		__m128i x, y, z;

		x = work[1];
		y = _mm_add_epi32(x, partkey[0]);
		z = _mm_add_epi32(mlt2_rotl_sse2(y, 1), y);
		z = _mm_sub_epi32(z, _mm_set1_epi32(1));

		out[0] = _mm_xor_si128(work[0], mlt2_rotl_sse2(z, 4));
		out[0] = _mm_xor_si128(out[0], z);
		out[1] = work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi3_sse2(const __m128i *partkey, __m128i *work)
	{
		__m128i out[2];
		__m128i x, y, z, a, b, c;

		x = work[0];
		y = _mm_add_epi32(x, partkey[1]);
		z = _mm_add_epi32(mlt2_rotl_sse2(y, 2), y);
		z = _mm_add_epi32(z, _mm_set1_epi32(1));
		a = _mm_xor_si128(mlt2_rotl_sse2(z, 8), z);
		b = _mm_add_epi32(a, partkey[2]);
		c = _mm_sub_epi32(mlt2_rotl_sse2(b, 1), b);

		out[0] = work[0];
		out[1] = _mm_xor_si128(work[1], mlt2_rotl_sse2(c, 16));
		out[1] = _mm_xor_si128(out[1], _mm_or_si128(c, x));

		work[0] = out[0];
		work[1] = out[1];
	}

	void mlt2_pi4_sse2(const __m128i *partkey, __m128i *work)
	{
		__m128i out[2];
		__m128i x, y;

		x = work[1];
		y = _mm_add_epi32(x, partkey[3]);

		out[0] = _mm_add_epi32(mlt2_rotl_sse2(y, 2), y);
		out[0] = _mm_add_epi32(out[0], _mm_set1_epi32(1));
		out[0] = _mm_xor_si128(out[0], work[0]);
		out[1] = work[1];

		work[0] = out[0];
		work[1] = out[1];
	}

	__m128i mlt2_rotl_sse2(__m128i x, int n)
	{
		__m128i mw0, mw1;

		mw0 = _mm_slli_epi32(x, n);
		mw1 = _mm_srli_epi32(x, 32 - n);
		return _mm_or_si128(mw0, mw1);
        }

private:
	__m128i workkey_sse2[8];
#endif //defined(__SSE2__)
};

#endif //MULTI2_SSE2_HPP__
