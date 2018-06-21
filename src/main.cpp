#include <cstdio>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <functional>
#include <deque>
#include <map>
#include <vector>

#include "packet_ts.hpp"
#include "psi_pat.hpp"
#include "psi_pmt.hpp"
#include "psi_ecm.hpp"
#include "smart_card.hpp"
#include "cardres_int.hpp"
#include "cardres_ecm.hpp"
#include "descrambler_ts.hpp"

#define SIZE_TS          188
#define SIZE_TS_CHUNK    (188 * 7)

struct context;
typedef std::function<int(context&, payload_ts&)> func_payload;

int proc_pat(context& c, payload_ts& pay);
int proc_pmt(context& c, payload_ts& pay);
int proc_ecm(context& c, payload_ts& pay);

struct context {
	void reset_ts_filter()
	{
		map_filter.clear();

		map_filter.insert(std::make_pair(0, proc_pat));
	}

	void add_ts_filter(uint32_t pid, func_payload f)
	{
		map_filter.insert(std::make_pair(pid, f));
	}

	void remove_ts_filter(uint32_t pid)
	{
		map_filter.erase(pid);
	}

	void add_pmt_filters_by_pat(psi_pat& pat)
	{
		for (auto& e : pat.progs) {
			if (e.program_number == 0)
				continue;

			printf("--PMT prg:%5d(0x%04x) pid:0x%04x\n",
				e.program_number, e.program_number,
				e.program_map_id);
			add_pmt_filter(e.program_map_id);
		}
	}

	void remove_pmt_filters_by_pat(psi_pat& pat)
	{
		for (auto& e : pat.progs) {
			if (e.program_number == 0)
				continue;

			remove_pmt_filter(e.program_map_id);
		}
		pat.progs.clear();
	}

	void add_pmt_filter(uint32_t pid)
	{
		last_pmt[pid].version_number = -1;

		add_ts_filter(pid, proc_pmt);
	}

	void remove_pmt_filter(uint32_t pid)
	{
		remove_ts_filter(pid);

		remove_ecm_filters_by_pmt(last_pmt[pid]);
	}

	void add_ecm_filters_by_pmt(psi_pmt& pmt)
	{
		for (auto& e : pmt.descs) {
			if (e->descriptor_tag != DESC_CA)
				continue;

			desc_ca& dsc = dynamic_cast<desc_ca&>(*e);

			printf("  --ECM pid:0x%04x\n", dsc.ca_pid);
			add_ecm_filter(dsc.ca_pid);
		}
	}

	void remove_ecm_filters_by_pmt(psi_pmt& pmt)
	{
		for (auto& e : pmt.descs) {
			if (e->descriptor_tag != DESC_CA)
				continue;

			desc_ca& dsc = dynamic_cast<desc_ca&>(*e);

			remove_ecm_filter(dsc.ca_pid);
		}
		pmt.descs.clear();
	}

	void add_ecm_filter(uint32_t pid)
	{
		last_ecm[pid].version_number = -1;

		add_ts_filter(pid, proc_ecm);
	}

	void remove_ecm_filter(uint32_t pid)
	{
		remove_ts_filter(pid);
	}

	void init_smartcard()
	{
		int ret;

		if (sc.is_valid())
			return;

		valid_descrambler = 0;

		ret = sc.connect(0);
		if (ret) {
			scrd.release();
			scrd.establish();
			scrd.enumerate_readers();
			scrd.dump();
		} else {
			//success
			return;
		}

		sc.set_reader(scrd);
		ret = sc.connect(0);
		if (ret)
			fprintf(stderr, "Cannot get smart card.\n");
	}

	void init_descrambler()
	{
		if (!sc.is_valid() || valid_descrambler)
			return;

		uint8_t sc_init[] = {
			//CLA, INS
			0x90, 0x30,
			//param 1, 2, length
			0x00, 0x00, 0x00,
		};
		uint8_t sc_init_recv[80];
		size_t nrecv = sizeof(sc_init_recv);
		uint8_t *key;
		uint64_t iv;

		sc.transmit(sc_init, sizeof(sc_init), sc_init_recv, &nrecv);
		if (nrecv == 0) {
			fprintf(stderr, "Cannot get initialize vector.\n");
			return;
		}

		bitstream<uint8_t *> bs(sc_init_recv, 0, nrecv);
		cardres_int crint;

		crint.read(bs);
		key = crint.descrambling_system_key;
		iv = crint.descrambler_cbc_initial_value;

		for (int i = 0; i < 0x2000; i++) {
			descrambler[i].set_system_key(key);
			descrambler[i].set_init_vector(iv);
		}
		valid_descrambler = 1;

		crint.dump();
	}

public:
	std::map<uint32_t, func_payload> map_filter;
	payload_ts payloads[0x2000];
	psi_pat last_pat;
	psi_pmt last_pmt[0x2000];
	psi_ecm last_ecm[0x2000];
	uint32_t es_ecm[0x2000];
	cardres_ecm last_res_ecm[0x2000];

	smart_card_reader scrd;
	smart_card sc;

	descrambler_ts descrambler[0x2000];
	int valid_descrambler;
};

void usage(int argc, char *argv[])
{
	fprintf(stderr, "usage: %s input address port [output]\n\n"
		"  input : Input file name, '-' means stdin\n"
		"  host  : Destination address\n"
		"  port  : Destination port\n"
		"  output: Output file name.\n",
		argv[0]);
}

int proc_ts(context& c, packet_ts& ts)
{
	if (ts.is_error())
		return 0;

	auto it = c.map_filter.find(ts.pid);
	if (it == c.map_filter.end())
		return 0;

	payload_ts& p = c.payloads[ts.pid];

	p.add_ts(ts);

	if (!p.is_valid() || !ts.payload_unit_start_indicator)
		return 0;
	if (p.get_payload().size() == 0)
		return 0;

	it->second(c, p);

	return 0;
}

int proc_pat(context& c, payload_ts& pay)
{
	auto buf = pay.get_payload();
	bitstream<std::vector<uint8_t>::iterator> bs(buf.begin(), 0, buf.size());
	psi_pat& last_pat = c.last_pat;
	psi_pat pat;

	pat.read(bs);
	if (pat.is_error()) {
		pat.print_error(stderr);
		return 0;
	}

	if (last_pat.version_number == pat.version_number)
		return 0;

	c.remove_pmt_filters_by_pat(last_pat);

	printf("PAT ver.%2d\n", pat.version_number);
	last_pat = pat;

	c.add_pmt_filters_by_pat(pat);

	//pat.dump();

	return 0;
}

int proc_pmt(context& c, payload_ts& pay)
{
	auto buf = pay.get_payload();
	packet_ts& ts = pay.get_first_ts();
	bitstream<std::vector<uint8_t>::iterator> bs(buf.begin(), 0, buf.size());
	psi_pmt& last_pmt = c.last_pmt[ts.pid];
	psi_pmt pmt;

	pmt.read(bs);
	if (pmt.is_error()) {
		pmt.print_error(stderr);
		return 0;
	}

	if (last_pmt.version_number == pmt.version_number)
		return 0;

	c.remove_ecm_filters_by_pmt(last_pmt);

	printf("  PMT ver.%2d prg:%5d(0x%04x) pid:0x%04x\n", pmt.version_number,
		pmt.program_number, pmt.program_number, ts.pid);
	last_pmt = pmt;

	c.add_ecm_filters_by_pmt(pmt);

	//Register new ES
	uint32_t default_ecm = 0x1fff;

	for (auto& e : pmt.descs) {
		if (e->descriptor_tag != DESC_CA)
			continue;

		desc_ca& dsc = dynamic_cast<desc_ca&>(*e);

		default_ecm = dsc.ca_pid;
	}

	for (auto& e : pmt.esinfos) {
		c.es_ecm[e.elementary_pid] = 0x1fff;

		if (default_ecm != 0x1fff)
			c.es_ecm[e.elementary_pid] = default_ecm;

		for (auto& e_es : e.descs) {
			if (e_es->descriptor_tag != DESC_CA)
				continue;

			desc_ca& dsc_es = dynamic_cast<desc_ca&>(*e_es);

			if (dsc_es.ca_pid != 0x1fff)
				c.es_ecm[e.elementary_pid] = dsc_es.ca_pid;
		}

		printf("  --ES type:0x%04x pid:0x%04x ecm:0x%04x\n",
			e.stream_type, e.elementary_pid,
			c.es_ecm[e.elementary_pid]);
	}

	//pmt.dump();

	return 0;
}

int proc_ecm(context& c, payload_ts& pay)
{
	auto buf = pay.get_payload();
	packet_ts& ts = pay.get_first_ts();
	bitstream<std::vector<uint8_t>::iterator> bs(buf.begin(), 0, buf.size());
	psi_ecm& last_ecm = c.last_ecm[ts.pid];
	psi_ecm ecm;
	cardres_ecm& last_res_ecm = c.last_res_ecm[ts.pid];
	cardres_ecm res_ecm;
	int ret;

	ecm.read(bs);
	if (ecm.is_error()) {
		ecm.print_error(stderr);
		return 0;
	}

	if (last_ecm.version_number == ecm.version_number)
		return 0;

	printf("  ECM ver.%2d pid:0x%04x\n", ecm.version_number,
		ts.pid);
	last_ecm = ecm;

	c.init_smartcard();
	c.init_descrambler();

	if (c.sc.is_valid()) {
		size_t len_sc_ecm = ecm.body.size() + 5 + 1;
		uint8_t sc_ecm[512] = {
			//CLA
			0x90,
			//INS
			0x34,
			//param 1, 2
			0x00, 0x00,
		};
		uint8_t sc_ecm_recv[512];
		size_t nrecv = sizeof(sc_ecm_recv);

		//cmd length, encrypted ECM
		sc_ecm[4] = ecm.body.size();
		for (size_t i = 0; i < ecm.body.size(); i++)
			sc_ecm[5 + i] = ecm.body[i];

		//res length
		sc_ecm[5 + ecm.body.size()] = 0x00;

		ret = c.sc.transmit(sc_ecm, len_sc_ecm, sc_ecm_recv, &nrecv);
		//printf("body:%d, nrecv:%d\n", (int)len_sc_ecm, (int)nrecv);

		if (!ret) {
			bitstream<uint8_t *> bs_ecm(sc_ecm_recv, 0, nrecv);

			res_ecm.read(bs_ecm);

			last_res_ecm = res_ecm;
			//res_ecm.dump();
		}
	}

	for (int i = 0; i < 0x2000; i++) {
		if (c.es_ecm[i] != ts.pid)
			continue;

		c.descrambler[i].set_data_key_odd(last_res_ecm.ks_odd);
		c.descrambler[i].set_data_key_even(last_res_ecm.ks_even);

		//printf("  --ES change key pid:0x%04x ecm:0x%04x\n",
		//	i, c.es_ecm[i]);
	}

	//ecm.dump();

	return 0;
}

int descramble_ts(context& c, packet_ts& ts)
{
	if (ts.is_error())
		return 0;
	if ((ts.transport_scrambling_control & 2) == 0)
		return 0;

	c.descrambler[ts.pid].descramble(ts);

	return 0;
}

int main(int argc, char *argv[])
{
	std::deque<char> buf_ts;
	std::deque<char> buf_sock;
	const char *fname, *hostname, *servname, *dumpname;
	int fd, sock, fd_dump;
	int port;
	size_t bufsize;
	char *buf;
	struct sockaddr_in saddr;
	ssize_t rsize;
	size_t cnt;
	int i;
	static struct context c;

	if (argc < 4) {
		usage(argc, argv);
		return -1;
	}

	fname = argv[1];
	hostname = argv[2];
	servname = argv[3];
	if (argc >= 4)
		dumpname = argv[4];
	else
		dumpname = NULL;

	bufsize = SIZE_TS_CHUNK;
	port = atoi(argv[3]);

	if (strcmp(fname, "-") == 0) {
		fd = 0;
	} else {
		fd = open(fname, O_RDONLY);
		if (fd == -1) {
			perror("open");
			fprintf(stderr, "Failed to open '%s'\n",
				fname);
			return -1;
		}
	}

	if (dumpname) {
		fd_dump = open(dumpname, O_RDWR | O_CREAT, 0644);
		if (fd_dump == -1) {
			perror("open(dump)");
			fprintf(stderr, "Failed to open '%s'\n",
				dumpname);
			return -1;
		}
	} else {
		fd_dump = -1;
	}

	buf = (char *)malloc(bufsize);
	if (!buf) {
		perror("malloc");
		return -1;
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket(INET, DGRAM)");
		fprintf(stderr, "Failed to connect '%s:%s'\n",
			hostname, servname);
		return -1;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = inet_addr(hostname);

	c.reset_ts_filter();

	cnt = 0;
	i = 0;
	printf("\n\n");
	while (1) {
		rsize = read(fd, buf, bufsize);
		if (rsize == -1) {
			fprintf(stderr, "Failed to read '%s'\n",
				fname);
			break;
		} else if (rsize == 0) {
			//EOF
			break;
		}

		//Search next sync byte of TS
		buf_ts.insert(buf_ts.end(), &buf[0], &buf[rsize]);
		while (buf_ts.size() > 0) {
			if (buf_ts.front() == 0x47)
				break;
			buf_ts.pop_front();
		}

		while (buf_ts.size() >= SIZE_TS) {
			bitstream<std::deque<char>::iterator> bs(buf_ts.begin(),
				0, SIZE_TS);
			packet_ts ts;

			ts.peek(bs);
			if (ts.pid != 0x1fff) {
				proc_ts(c, ts);
				descramble_ts(c, ts);
				ts.poke(bs);

				buf_sock.insert(buf_sock.end(), buf_ts.begin(),
					buf_ts.begin() + SIZE_TS);
			}

			buf_ts.erase(buf_ts.begin(),
				buf_ts.begin() + SIZE_TS);
		}

		//Send TS
		while (buf_sock.size() >= SIZE_TS_CHUNK) {
			uint8_t tmp[SIZE_TS_CHUNK];

			for (int i = 0; i < SIZE_TS_CHUNK; i++)
				tmp[i] = buf_sock[i];

			sendto(sock, tmp, SIZE_TS_CHUNK, 0,
				(struct sockaddr *)&saddr, sizeof(saddr));

			if (fd_dump != -1)
				write(fd_dump, tmp, SIZE_TS_CHUNK);

			buf_sock.erase(buf_sock.begin(),
				buf_sock.begin() + SIZE_TS_CHUNK);
		}

		cnt += rsize;

		if (i > 1000) {
			printf("\rcnt:%.3fMB    ", (double)cnt / 1024 / 1024);
			fflush(stdout);
			i = 0;
		}
		i++;
	}

	free(buf);
	close(sock);
	close(fd);
	if (fd_dump != -1)
		close(fd_dump);

	return 0;
}
