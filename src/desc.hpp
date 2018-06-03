#ifndef DESC_HPP__
#define DESC_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include "packet.hpp"

enum desc_type {
	//ISO 13818-1
	DESC_VIDEO_STREAM = 0x02,
	DESC_AUDIO_STREAM = 0x03,
	DESC_CA = 0x09,

	//ARIB STD B10
	DESC_STREAM_IDENTIFIER = 0x52,
	DESC_DIGITAL_COPY_CONTROL = 0xc1,
	DESC_VIDEO_DECODE_CONTROL = 0xc8,
	DESC_DATA_COMPONENT = 0xfd,
};

class desc_base : public packet {
public:
	desc_base() :
		descriptor_tag(0),
		descriptor_length(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<desc_base> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		descriptor_tag    = bs.get_bits(8);
		descriptor_length = bs.get_bits(8);
		if (descriptor_length > bs.remain()) {
			this->set_error(EINVAL,
				"descriptor too large, len:%d, remain:%d",
				(int)descriptor_length,
				(int)bs.remain());
			return;
		}
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<desc_base> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf(FORMAT_STRING_N
			FORMAT_STRING,
			"descriptor_tag"   , descriptor_tag   , get_descriptor_tag_name(descriptor_tag),
			"descriptor_length", descriptor_length);
	}

	static const char *get_descriptor_tag_name(uint32_t id)
	{
		const char *name = "unknown";

		switch (id) {
		case DESC_VIDEO_STREAM:
			name = "VIDEO_STREAM";
			break;
		case DESC_AUDIO_STREAM:
			name = "AUDIO_STREAM";
			break;
		case DESC_CA:
			name = "CA";
			break;
		case DESC_STREAM_IDENTIFIER:
			name = "STREAM_IDENTIFIER";
			break;
		case DESC_DIGITAL_COPY_CONTROL:
			name = "DIGITAL_COPY_CONTROL";
			break;
		case DESC_VIDEO_DECODE_CONTROL:
			name = "VIDEO_DECODE_CONTROL";
			break;
		case DESC_DATA_COMPONENT:
			name = "DATA_COMPONENT";
			break;
		}

		return name;
	}

public:
	uint32_t descriptor_tag;
	uint32_t descriptor_length;
};

class desc_unknown : public desc_base {
public:
	desc_unknown()
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<desc_unknown> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		desc_base::read_stub(bs);
		if (is_error())
			return;

		bs.skip_bits(descriptor_length * 8);
	}

	virtual void dump()
	{
		desc_base::dump();
	}
};

#endif //DESC_HPP__
