#define BIND_8_COMPAT

#include <arpa/nameser.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef unsigned char byte;

static void
noop(int sig) {
	(void)sig;
}

static int
readall(int sock, byte *buf, int len) {
	int got = 0;
	for (int r = len; r > 0 && len > got; got += r) {
		r = read(sock, buf + got, len - got);
		if (r < 0)
			err(1, "read");
	}
	return (got);
}

static unsigned
get16(byte *buf, size_t max, size_t off) {
	assert(off + 2 <= max);
	return(buf[off] << 8 | buf[off+1]);
}

static unsigned
get32(byte *buf, size_t max, size_t off) {
	assert(off + 4 <= max);
	return(buf[off+0] << 24 | buf[off+1] << 16 |
	       buf[off+2] << 8 | buf[off+3]);
}

static size_t
dump16(byte *buf, size_t max, size_t off, const char *caption) {
	unsigned u = get16(buf, max, off);
	printf("%04zx %04x %s %u\n", off, u, caption, u);
	return(off+2);
}

static size_t
dump_bytes(byte *buf, size_t max, size_t off, size_t len, const char *caption) {
	assert(off + len <= max);
	while(len > 0) {
		printf("%04zx ", off);
		size_t line = len >= 32 ? 32 : len % 32;
		len -= line;
		while(line-- > 0)
			printf("%02x", buf[off++]);
		printf(" %s\n", caption);
	}
	return(off);
}

static size_t
dump_name(byte *buf, size_t max, size_t off) {
	char name[512];
	char *cp = name;
	size_t name_len = 0;

	uint8_t *end = buf + max;
	uint8_t *start = buf + off;
	uint8_t *marker = start;
	uint8_t *cursor = start;
	uint8_t *consumed = NULL;
	uint8_t *firsthop = NULL;

	while (cursor < end) {
		uint8_t label_len = *cursor++;
		if (label_len < 64) {
			name_len += label_len + 1;
			assert(name_len <= 255);
			assert(cursor + label_len <= end);
			if (label_len == 0) {
				goto root_label;
			}
			while (label_len-- > 0) {
				uint8_t c = *cursor++;
				if (c == '-' || c == '_' ||
				    ('0' <= c && c <= '9') ||
				    ('A' <= c && c <= 'Z') ||
				    ('a' <= c && c <= 'z')) {
					*cp++ = c;
				} else {
					*cp++ = '?';
				}
			}
			*cp++ = '.';
		} else {
			assert(label_len >= 192);
			uint32_t hi = label_len & 0x3F;
			assert(cursor < end);
			uint32_t lo = *cursor++;
			uint8_t *pointer = buf + (256 * hi + lo);
			assert(pointer < marker);
			if (firsthop == NULL) {
				firsthop = pointer;
				consumed = cursor;
				*cp++ = '(';
				*cp++ = '.';
			}
			cursor = marker = pointer;
		}
	}
	assert(cursor < end);

root_label:
	if (name_len == 1) {
		*cp++ = '.';
	}
	size_t space = name + sizeof(name) - cp;
	if (firsthop == NULL) {
		consumed = cursor;
		snprintf(cp, space, " @");
	} else {
		snprintf(cp, space, ") @ %04x", (unsigned)(firsthop - buf));
	}
	return(dump_bytes(buf, max, off, consumed - start, name));
}

static size_t
dump_question(byte *buf, size_t max, size_t off) {
	off = dump_name(buf, max, off);
	unsigned ty = get16(buf, max, off + 0);
	unsigned cl = get16(buf, max, off + 2);
	char caption[64];
	snprintf(caption, sizeof(caption), "%s %s", p_type(ty), p_class(cl));
	return(dump_bytes(buf, max, off, 4, caption));
}

static size_t
dump_rr(byte *buf, size_t max, size_t off) {
	off = dump_name(buf, max, off);
	unsigned ty = get16(buf, max, off + 0);
	unsigned cl = get16(buf, max, off + 2);
	unsigned ttl = get32(buf, max, off + 4);
	unsigned rdlen = get16(buf, max, off + 8);
	char caption[64];
	snprintf(caption, sizeof(caption), "%s %s %u \\# %u",
		 p_type(ty), p_class(cl), ttl, rdlen);
	off = dump_bytes(buf, max, off, 10, caption);
	unsigned end = off + rdlen;
	switch (ty) {
	case ns_t_cname:
	case ns_t_ns:
		off = dump_name(buf, max, off);
		break;
	case ns_t_nsec:
		off = dump_name(buf, max, off);
		off = dump_bytes(buf, max, off, end - off, "bitmap");
		break;
	case ns_t_rrsig:
		snprintf(caption, sizeof(caption), "RRSIG %s",
			 p_type(get16(buf, max, off)));
		off = dump_bytes(buf, max, off, 18, caption);
		off = dump_name(buf, max, off);
		off = dump_bytes(buf, max, off, end - off, "");
		break;
	case ns_t_soa:
		off = dump_name(buf, max, off);
		off = dump_name(buf, max, off);
		off = dump_bytes(buf, max, off, 20, "timers");
		break;
	default:
		off = dump_bytes(buf, max, off, rdlen, "");
		break;
	}
	assert(off == end);
	return(off);
}

static size_t
dump_section(byte *buf, size_t max, size_t off, unsigned count, const char *caption) {
	for (unsigned rr = 0; rr < count; rr++) {
		printf("%04zx %s %u\n", off, caption, rr);
		off = dump_rr(buf, max, off);
	}
	return(off);
}

static void
dump_message(byte *buf, size_t max) {
	assert(max < 0x10000);
	size_t off = 0;
	dump_bytes(buf, max, off, 12, "header");
	off = dump16(buf, max, off, "id");
	off = dump_bytes(buf, max, off, 2, "flags");
	unsigned qdcount = get16(buf, max, off+0);
	unsigned ancount = get16(buf, max, off+2);
	unsigned nscount = get16(buf, max, off+4);
	unsigned arcount = get16(buf, max, off+6);
	off = dump_bytes(buf, max, off, 8, "RR counts");
	assert(qdcount < 2);
	if(qdcount > 0)
		off = dump_question(buf, max, off);
	off = dump_section(buf, max, off, ancount, "answer");
	off = dump_section(buf, max, off, nscount, "authority");
	off = dump_section(buf, max, off, arcount, "additional");
	assert(off == max);
}

static int
usage(void) {
	fprintf(stderr,
		"usage: dumpaxfr [-46dx] [-p port] server zone [prefix]\n");
	return (1);
}

int
main(int argc, char *argv[]) {
	const char *zone = NULL;
	const char *server = NULL;
	const char *port = "domain";
	const char *prefix = "xfer";
	int protocol = SOCK_STREAM;
	int family = PF_UNSPEC;
	bool debug = false;
	bool expand = false;
	int r;

	while ((r = getopt(argc, argv, "46dp:x")) != -1)
		switch (r) {
		case ('4'):
			family = PF_INET;
			continue;
		case ('6'):
			family = PF_INET6;
			continue;
		case ('d'):
			debug = true;
			continue;
		case ('p'):
			port = optarg;
			continue;
		case ('x'):
			expand = true;
			continue;
		default:
			exit(usage());
		}
	argc -= optind;
	argv += optind;

	if (argc != 2 && argc != 3)
		exit(usage());

	server = argv[0];
	zone = argv[1];
	if(argv[2])
		prefix = argv[2];

	res_init();
	if (debug)
		_res.options |= RES_DEBUG;

	byte request[NS_PACKETSZ + 2];
	int reqlen = res_mkquery(ns_o_query, zone, ns_c_in, ns_t_axfr, NULL, 0,
				 NULL, request + 2, NS_PACKETSZ);
	if (reqlen < 0)
		errx(1, "could not make DNS AXFR query for %s", zone);
	((HEADER *)(request + 2))->rd = 0;
	if (debug)
		res_pquery(&_res, request + 2, reqlen, stdout);
	request[0] = (reqlen & 0xff00) >> 8;
	request[1] = (reqlen & 0xff);

	int sock = -1;

	struct addrinfo hints, *ai0, *ai;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = protocol;
	r = getaddrinfo(server, port, &hints, &ai0);
	if (r != 0)
		errx(1, "%s: %s", server, gai_strerror(r));

	for (ai = ai0; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != family && family != PF_UNSPEC)
			continue;
		if (debug) {
			char host[NI_MAXHOST], serv[NI_MAXSERV];
			int e = getnameinfo(ai->ai_addr, ai->ai_addrlen, host,
					    sizeof(host), serv, sizeof(serv),
					    NI_NUMERICHOST | NI_NUMERICSERV);
			if (e == 0)
				printf("; -> %s [%s#%s]\n",
				       server, host, serv);
			else
				printf("; -> %s (%s)\n",
				       server, gai_strerror(e));
		}
		sock = socket(ai->ai_family, protocol, 0);
		if (sock < 0) {
			warn("socket");
			continue;
		}
		r = connect(sock, ai->ai_addr, ai->ai_addrlen);
		if (r < 0) {
			warn("connect");
			close(sock);
			sock = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(ai0);

	if (sock < 0)
		errx(1, "could not connect to [%s#%s]", server, port);

	r = write(sock, request, reqlen + 2);
	if (r < 0) {
		err(1, "write");
	}
	if (r != reqlen + 2) {
		errx(1, "truncated write");
	}

	struct sigaction sa = { 0 };
	sa.sa_handler = noop;
	sigaction(SIGALRM, &sa, &sa);

	for (int message = 0;; message++) {
		if (expand || debug)
			printf("; message %d\n", message);

		alarm(1);
		byte reply[NS_MAXMSG];
		readall(sock, reply, 2);
		int replylen = reply[0] << 8 | reply[1];
		if (debug)
			printf("; expect %d\n", replylen);
		replylen = readall(sock, reply, replylen);
		if (debug)
			printf("; received %d\n", replylen);

		if (expand)
			dump_message(reply, replylen);
		if (debug)
			res_pquery(&_res, reply, replylen, stdout);

		char filename[1024];
		snprintf(filename, sizeof(filename), "%s_%s_%s_%d.bin",
			 prefix, server, zone, message);

		int fd = creat(filename, 0666);
		if (fd < 0)
			err(1, "creat(%s)", filename);
		r = write(fd, reply, replylen);
		if (r < 0)
			err(1, "write(%s)", filename);
		close(fd);
		if (debug)
			printf("; creat %s (%d bytes)\n",
			       filename, replylen);
	}
}
