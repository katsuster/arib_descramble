#ifndef SMART_CARD_HPP__
#define SMART_CARD_HPP__

#include <cerrno>
#include <cstdint>
#include <cinttypes>

#include <string>
#include <vector>

#include <winscard.h>

class smart_card_reader {
public:
	smart_card_reader() :
		valid(0)
	{
		establish();
	}

	virtual ~smart_card_reader()
	{
		release();
	}

	const SCARDCONTEXT get_context() const
	{
		return scc;
	}

	SCARDCONTEXT get_context()
	{
		return scc;
	}

	int is_valid() const
	{
		return valid;
	}

	int establish()
	{
		LONG ret;

		if (valid)
			return -EBUSY;

		ret = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &scc);
		if (ret != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardEstablishContext() failed.\n");
			return -EIO;
		}

		valid = 1;

		return 0;
	}

	void release()
	{
		LONG ret;

		if (!valid)
			return;

		ret = SCardReleaseContext(scc);
		if (ret != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardReleaseContext() failed.\n");
		}

		valid = 0;
	}

	int enumerate_readers()
	{
		LPTSTR mstrgrp = NULL, strgrp;
		DWORD cch = SCARD_AUTOALLOCATE;
		LONG ret;

		name_readers.clear();

		ret = SCardListReaders(scc, NULL, (LPTSTR)&mstrgrp, &cch);
		if (ret == SCARD_E_NO_READERS_AVAILABLE) {
			fprintf(stderr, "No cards.\n");
			return -ENOENT;
		} else if (ret != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardListReaders() failed.\n");
			return -EIO;
		}

		strgrp = mstrgrp;
		while (*strgrp != '\0') {
			name_readers.push_back(strgrp);
			strgrp = strgrp + strlen(strgrp) + 1;
		}

		SCardFreeMemory(scc, mstrgrp);

		return 0;
	}

	const std::vector<std::string>& get_readers() const
	{
		return name_readers;
	}

	std::vector<std::string>& get_readers()
	{
		return name_readers;
	}

	void dump() const
	{
		for (auto& e : name_readers) {
			printf("card: %s\n", e.c_str());
		}
	}

private:
	SCARDCONTEXT scc;
	std::vector<std::string> name_readers;
	int valid;
};

class smart_card {
public:
	smart_card() :
		scrd(NULL), valid(0)
	{
	}

	smart_card(smart_card_reader& r) :
		scrd(&r), valid(0)
	{
	}

	virtual ~smart_card()
	{
		disconnect();
	}

	int is_valid()
	{
		return scrd && valid;
	}

	void set_reader(smart_card_reader& r)
	{
		scrd = &r;
	}

	int connect(size_t n)
	{
		DWORD prot;
		LONG ret;

		if (!scrd || valid || n >= scrd->get_readers().size())
			return -ENOENT;

		auto& rd = scrd->get_readers();

		ret = SCardConnect(scrd->get_context(), rd[n].c_str(),
			SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &sch, &prot);
		if (ret != SCARD_S_SUCCESS) {
			fprintf(stderr, "ScardConnect() failed.\n");
			return -EIO;
		}

		valid = 1;

		return 0;
	}

	void disconnect()
	{
		LONG ret;

		if (!scrd || !valid)
			return;

		ret = SCardDisconnect(sch, SCARD_LEAVE_CARD);
		if (ret != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardDisconnect() failed.\n");
		}

		valid = 0;
	}

	int transmit(void *buf_send, size_t nsend, void *buf_recv, size_t *nrecv)
	{
		DWORD nreceived = *nrecv;
		LONG ret;

		if (!scrd || !valid)
			return -EBADF;

		ret = SCardTransmit(sch, SCARD_PCI_T1,
			(LPBYTE)buf_send, nsend, NULL,
			(LPBYTE)buf_recv, &nreceived);
		if (ret != SCARD_S_SUCCESS) {
			fprintf(stderr, "SCardTransmit() failed.\n");
			valid = 0;
			return -EIO;
		}

		*nrecv = nreceived;

		return 0;
	}

private:
	smart_card_reader *scrd;
	SCARDHANDLE sch;
	int valid;
};

#endif //SMART_CARD_HPP__
