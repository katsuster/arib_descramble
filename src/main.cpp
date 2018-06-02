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

#define SIZE_TS          188
#define SIZE_TS_CHUNK    (188 * 7)

void usage(int argc, char *argv[])
{
	fprintf(stderr, "usage: %s input address port [output]\n\n"
		"  input : Input file name, '-' means stdin\n"
		"  host  : Destination address\n"
		"  port  : Destination port\n"
		"  output: Output file name.\n",
		argv[0]);
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
			buf_sock.insert(buf_sock.end(), buf_ts.begin(),
				buf_ts.begin() + SIZE_TS);

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
