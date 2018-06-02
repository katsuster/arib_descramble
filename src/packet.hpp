#ifndef PACKET_HPP__
#define PACKET_HPP__

#include <cstdarg>
#include <cstdint>
#include <cinttypes>

#include <deque>
#include <string>
#include <vector>

#include "bitstream.hpp"

#define FORMAT_NAME         "    %40s: "
#define FORMAT_STRING       "    %40s: 0x%08x\n"
#define FORMAT_STRING_N     "    %40s: 0x%08x(%s)\n"
#define FORMAT_STRING_LL    "    %40s: 0x%08" PRIx64 "\n"
#define FORMAT_STRING_LL_N  "    %40s: 0x%08" PRIx64 "(%s)\n"

class packet {
public:
	packet() :
		no_err(0)
	{
	}

	virtual ~packet()
	{
	}

	virtual bool is_error() const
	{
		return no_err;
	}

	virtual int get_error_num() const
	{
		return no_err;
	}

	virtual const char *get_error_msg() const
	{
		return msg_err.c_str();
	}

	virtual void set_error(int f)
	{
		set_error(f, "");
	}

	virtual void set_error(int f, const char *msg, ...)
	{
		va_list ap;
		int size;
		char *buf;

		no_err = f;

		va_start(ap, msg);
		size = vsnprintf(NULL, 0, msg, ap);
		va_end(ap);

		va_start(ap, msg);
		buf = (char *)calloc(size + 4, sizeof(char));
		vsnprintf(buf, size + 1, msg, ap);
		msg_err = buf;
		free(buf);
		va_end(ap);
	}

	virtual void dup_error(const packet& o)
	{
		set_error(o.get_error_num(), o.get_error_msg());
	}

	virtual void clear_error()
	{
		no_err = 0;
		msg_err = "";
	}

	virtual void print_error(FILE *f) const
	{
		fprintf(f, "Error %d, '%s'.\n", no_err, msg_err.c_str());
	}

	template <class T>
	void peek(bitstream<T>& bs)
	{
		size_t p = bs.position_bits();

		read(bs);
		bs.position_bits(p);
	}

	template <class T>
	void read(bitstream<T>& bs)
	{
		get_read_stub()(this, bs);
	}

	struct stub_base__empty;

	template <class K, class S = packet>
	struct stub_derived__read : public S::stub_base__read {
		virtual ~stub_derived__read()
		{
		}

		virtual void operator()(packet *p,
			bitstream<uint8_t *>& v) const
		{
			return static_cast<K *>(p)->read_stub(v);
		}

		virtual void operator()(packet *p,
			bitstream<char *>& v) const
		{
			return static_cast<K *>(p)->read_stub(v);
		}

		virtual void operator()(packet *p,
			bitstream<std::vector<uint8_t>::iterator>& v) const
		{
			return static_cast<K *>(p)->read_stub(v);
		}

		virtual void operator()(packet *p,
			bitstream<std::deque<char>::iterator>& v) const
		{
			return static_cast<K *>(p)->read_stub(v);
		}
	};

	typedef stub_derived__read<packet, stub_base__empty> stub_base__read;
	virtual const stub_base__read& get_read_stub(void) const = 0;

	template <class T>
	void read_stub(bitstream<T>& bs)
	{
		printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
	}

	template <class T>
	void poke(bitstream<T>& bs)
	{
		size_t p = bs.position_bits();

		write(bs);
		bs.position_bits(p);
	}

	template <class T>
	void write(bitstream<T>& bs)
	{
		get_write_stub()(this, bs);
	}

	template <class K, class S = packet>
	struct stub_derived__write : public S::stub_base__write {
		virtual ~stub_derived__write()
		{
		}

		virtual void operator()(packet *p,
			bitstream<uint8_t *>& v) const
		{
			return static_cast<K *>(p)->write_stub(v);
		}

		virtual void operator()(packet *p,
			bitstream<char *>& v) const
		{
			return static_cast<K *>(p)->write_stub(v);
		}

		virtual void operator()(packet *p,
			bitstream<std::vector<uint8_t>::iterator>& v) const
		{
			return static_cast<K *>(p)->write_stub(v);
		}

		virtual void operator()(packet *p,
			bitstream<std::deque<char>::iterator>& v) const
		{
			return static_cast<K *>(p)->write_stub(v);
		}
	};

	typedef stub_derived__write<packet, stub_base__empty> stub_base__write;
	virtual const stub_base__write& get_write_stub(void) const = 0;

	template <class T>
	void write_stub(bitstream<T>& bs)
	{
		printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
	}

	struct stub_base__empty {
		struct stub_base__read {};
		struct stub_base__write {};
	};

private:
	int no_err;
	std::string msg_err;
};

#endif //PACKET_HPP__
