#ifndef BIT_STREAM_HPP__
#define BIT_STREAM_HPP__

#include <cstdint>

template <class RandomIterator>
class bitstream {
public:
	bitstream(RandomIterator buffer, size_t offset, size_t length)
		: buf(buffer), off(offset), len(length), pos(0)
	{
	}

	RandomIterator buffer()
	{
		return buf;
	}

	const RandomIterator buffer() const
	{
		return buf;
	}

	size_t offset() const
	{
		return off;
	}

	size_t length() const
	{
		return len;
	}

	ssize_t remain() const
	{
		return length() - position();
	}

	ssize_t remain_bits() const
	{
		return length() - position();
	}

	size_t position() const
	{
		if (!is_align_byte()) {
			fprintf(stderr, "bit position %d is not byte aligned.\n",
				(int)position_bits());
		}

		return pos >> 3;
	}

	size_t position_bits() const
	{
		return pos;
	}

	void position_bits(size_t newpos)
	{
		pos = newpos;
	}

	bool is_align_byte() const
	{
		return (pos & 0x7) == 0;
	}

	void skip(size_t n)
	{
		position_bits(position_bits() + (n << 3));
	}

	void skip_bits(size_t n)
	{
		position_bits(position_bits() + n);
	}

	uint64_t get_bits(size_t n)
	{
		uint64_t result;

		result = get_bits(position_bits(), n);
		position_bits(position_bits() + n);

		return result;
	}

	uint64_t get_bits(size_t st, size_t n)
	{
		size_t epos, remain;
		uint8_t elem;
		uint64_t result = 0;

		epos = st >> 3;
		remain = 8 - (st & 0x7);
		elem = buf[off + epos];

		while (n > remain) {
			//Add all remain bits
			n -= remain;
			result |= get_right_bits(remain, elem) << n;
			//Go to next
			epos += 1;
			elem = buf[off + epos];
			remain = 8;
		}

		if (n > 0) {
			//Read n bits from current
			result |= get_right_bits(n, elem >> (remain - n));
		}

		return result;
	}

	void set_bits(size_t n, uint64_t val)
	{
		set_bits(position_bits(), n, val);
		position_bits(position_bits() + n);
	}

	void set_bits(size_t st, size_t n, uint64_t val)
	{
		size_t epos, remain;
		uint8_t elem;

		epos = st >> 3;
		remain = 8 - (st & 0x7);
		elem = buf[off + epos];

		while (n > remain) {
			//Add all remain bits
			n -= remain;
			elem &= ~get_right_bits(remain, -1);
			elem |= get_right_bits(remain, val >> n);
			buf[off + epos] = elem;
			//Go to next
			epos += 1;
			elem = buf[off + epos];
			remain = 8;
		}

		if (n > 0) {
			//Write n bits from current
			elem &= ~(get_right_bits(n, -1) << (remain - n));
			elem |= get_right_bits(n, val) << (remain - n);
			buf[off + epos] = elem;
		}
	}

protected:
	uint64_t get_right_bits(size_t n, const uint64_t val)
	{
		size_t s = 64 - n;

		if (n == 0) {
			return 0;
		} else {
			return (val << s) >> s;
		}
	}

private:
	RandomIterator buf;
	//in bytes
	size_t off;
	//in bytes
	size_t len;
	//in bits
	size_t pos;

};

#endif //BIT_STREAM_HPP__
