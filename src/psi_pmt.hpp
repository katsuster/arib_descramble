#ifndef PSI_PMT_HPP__
#define PSI_PMT_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include <memory>
#include <vector>

#include "psi.hpp"
#include "desc.hpp"
#include "desc_ca.hpp"
#include "factory_desc.hpp"

enum stream_type {
	STRM_ISO_11172_VIDEO     = 0x01,
	STRM_H262_VIDEO          = 0x02,
	STRM_ISO_11172_AUDIO     = 0x03,
	STRM_ISO_13818_3_AUDIO   = 0x04,
	STRM_H222_0_PRIVATE      = 0x05,
	STRM_H222_0_PES          = 0x06,
	STRM_ISO_13818_6_TYPE_A  = 0x0a,
	STRM_ISO_13818_6_TYPE_B  = 0x0b,
	STRM_ISO_13818_6_TYPE_C  = 0x0c,
	STRM_ISO_13818_6_TYPE_D  = 0x0d,
	STRM_ISO_13818_7_AUDIO   = 0x0f,
	STRM_ISO_14496_2_VISUAL  = 0x10,
	STRM_ISO_14496_3_AUDIO   = 0x11,
	STRM_ISO_14496_1_PES     = 0x12,
	STRM_ISO_14496_1_SECTION = 0x13,
	STRM_ISO_14496_10_VIDEO  = 0x1b,
};

class pmt_esinfo : public packet {
public:
	pmt_esinfo() :
		stream_type(0),
		elementary_pid(0),
		es_info_length(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<pmt_esinfo> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		stream_type    = bs.get_bits(8);
		bs.skip_bits(3);
		elementary_pid = bs.get_bits(13);
		bs.skip_bits(4);
		es_info_length = bs.get_bits(12);
		if (es_info_length > (size_t)bs.remain()) {
			this->set_error(EINVAL,
				"PMT ES info too large, len:%d, remain:%d",
				(int)es_info_length,
				(int)bs.remain());
			return;
		}

		uint32_t e = bs.position() + es_info_length;
		while (bs.position() < e) {
			desc_base ds;

			ds.peek(bs);
			if (ds.is_error()) {
				dup_error(ds);
				return;
			}

			std::shared_ptr<desc_base> dsp(factory_desc::create_desc(ds.descriptor_tag));

			dsp->read(bs);
			if (dsp->is_error()) {
				dup_error(*dsp);
				return;
			}
			descs.push_back(dsp);
		}
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<pmt_esinfo> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf("  " FORMAT_STRING_N
			"  " FORMAT_STRING
			"  " FORMAT_STRING,
			"stream_type"   , stream_type   , get_stream_type_name(stream_type),
			"elementary_pid", elementary_pid,
			"es_info_length", es_info_length);

		for (size_t i = 0; i < descs.size(); i++) {
			printf("      descs[%d]\n", (int)i);
			descs[i]->dump();
		}
	}

	static const char *get_stream_type_name(uint32_t id)
	{
		const char *name = "unknown";

		switch (id) {
		case STRM_ISO_11172_VIDEO:
			name = "ISO_11172_VIDEO";
			break;
		case STRM_H262_VIDEO:
			name = "H262_VIDEO";
			break;
		case STRM_ISO_11172_AUDIO:
			name = "ISO_11172_AUDIO";
			break;
		case STRM_ISO_13818_3_AUDIO:
			name = "ISO_13818_3_AUDIO";
			break;
		case STRM_H222_0_PRIVATE:
			name = "H222_0_PRIVATE";
			break;
		case STRM_H222_0_PES:
			name = "H222_0_PES";
			break;
		case STRM_ISO_13818_6_TYPE_A:
			name = "ISO_13818_6_TYPE_A";
			break;
		case STRM_ISO_13818_6_TYPE_B:
			name = "ISO_13818_6_TYPE_B";
			break;
		case STRM_ISO_13818_6_TYPE_C:
			name = "ISO_13818_6_TYPE_C";
			break;
		case STRM_ISO_13818_6_TYPE_D:
			name = "ISO_13818_6_TYPE_D";
			break;
		case STRM_ISO_13818_7_AUDIO:
			name = "ISO_13818_7_AUDIO";
			break;
		case STRM_ISO_14496_2_VISUAL:
			name = "ISO_14496_2_VISUAL";
			break;
		case STRM_ISO_14496_3_AUDIO:
			name = "ISO_14496_3_AUDIO";
			break;
		case STRM_ISO_14496_1_PES:
			name = "ISO_14496_1_PES";
			break;
		case STRM_ISO_14496_1_SECTION:
			name = "ISO_14496_1_SECTION";
			break;
		case STRM_ISO_14496_10_VIDEO:
			name = "ISO_14496_10_VIDEO";
			break;
		}

		return name;
	}

public:
	uint32_t stream_type;
	uint32_t elementary_pid;
	uint32_t es_info_length;

	std::vector<std::shared_ptr<desc_base>> descs;
};

class psi_pmt : public psi_base {
public:
	psi_pmt() :
		program_number(0),
		version_number(-1),
		current_next_indicator(0),
		section_number(0),
		last_section_number(0),
		pcr_pid(0),
		program_info_length(0),
		crc_32(0)
	{
	}

	virtual const packet::stub_base__read& get_read_stub() const
	{
		static const packet::stub_derived__read<psi_pmt> s;
		return s;
	}

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		uint32_t e;

		psi_base::read_stub(bs);
		if (is_error())
			return;

		program_number         = bs.get_bits(16);
		bs.skip_bits(2);
		version_number         = bs.get_bits(5);
		current_next_indicator = bs.get_bits(1);
		section_number         = bs.get_bits(8);
		last_section_number    = bs.get_bits(8);
		bs.skip_bits(3);
		pcr_pid                = bs.get_bits(13);
		bs.skip_bits(4);
		program_info_length    = bs.get_bits(12);
		if (program_info_length > (size_t)bs.remain()) {
			set_error(EINVAL,
				"PMT program_info too large, len:%d, remain:%d",
				(int)program_info_length,
				(int)bs.remain());
			return;
		}

		descs.clear();
		e = bs.position() + program_info_length;
		while (bs.position() < e) {
			desc_base ds;

			ds.peek(bs);
			if (ds.is_error()) {
				dup_error(ds);
				return;
			}

			std::shared_ptr<desc_base> dsp(factory_desc::create_desc(ds.descriptor_tag));

			dsp->read(bs);
			if (dsp->is_error()) {
				dup_error(*dsp);
				return;
			}
			descs.push_back(dsp);
		}

		//-9: size of section_length .. last_section_number
		//-4: size of crc32
		int n = section_length - 9 - 4 - program_info_length;
		if (n < 0) {
			set_error(EINVAL,
				"PMT ES info too small, len:%d", n);
			return;
		}

		esinfos.clear();
		e = bs.position() + n;
		while (bs.position() < e) {
			pmt_esinfo es;

			es.read(bs);
			if (es.is_error()) {
				dup_error(es);
				return;
			}
			esinfos.push_back(es);
		}

		crc_32 = bs.get_bits(32);
	}

	virtual const packet::stub_base__write& get_write_stub() const
	{
		static const packet::stub_derived__write<psi_pmt> s;
		return s;
	}

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
	}

	virtual void dump()
	{
		printf("PMT -----\n");

		psi_base::dump();
		printf(FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING
			FORMAT_STRING,
			"program_number"        , program_number        ,
			"version_number"        , version_number        ,
			"current_next_indicator", current_next_indicator,
			"section_number"        , section_number        ,
			"last_section_number"   , last_section_number   ,
			"pcr_pid"               , pcr_pid               ,
			"program_info_length"   , program_info_length   ,
			"crc_32"                , crc_32                );

		for (size_t i = 0; i < descs.size(); i++) {
			printf("    descs[%d]\n", (int)i);
			descs[i]->dump();
		}

		for (size_t i = 0; i < esinfos.size(); i++) {
			printf("    esinfos[%d]\n", (int)i);
			esinfos[i].dump();
		}
	}

public:
	uint32_t program_number;
	uint32_t version_number;
	uint32_t current_next_indicator;
	uint32_t section_number;
	uint32_t last_section_number;
	uint32_t pcr_pid;
	uint32_t program_info_length;
	uint32_t crc_32;

	std::vector<std::shared_ptr<desc_base>> descs;
	std::vector<pmt_esinfo> esinfos;
};

#endif //PSI_PMT_HPP__
