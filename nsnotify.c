/* nsnotify: send DNS NOTIFY messages to lots of targets
 *
 * Written by Tony Finch <dot@dotat.at> in Cambridge.
 *
 * Permission is hereby granted to use, copy, modify, and/or
 * distribute this software for any purpose with or without fee.
 *
 * This software is provided 'as is', without warranty of any kind.
 * In no event shall the authors be liable for any damages arising
 * from the use of this software.
 *
 * SPDX-License-Identifier: 0BSD OR MIT-0
 */

#define BIND_8_COMPAT

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/nameser.h>
#include <netinet/in.h>

#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <unistd.h>

#include "version.h"

typedef unsigned char byte;

static const char what_ident[] =
    "@(#) $Program: nsnotify $\n"
    "@(#) $Version: " VERSION " $\n"
    "@(#) $Date:    " REVDATE " $\n"
    "@(#) $Author:  Tony Finch (dot@dotat.at) $\n"
    "@(#) $URL:     http://dotat.at/prog/nsnotifyd/ $\n"
;

static int
version(void) {
	const char *p = what_ident;
	for(;;) {
		while(*++p != '$')
			if(*p == '\0')
				return(0);
		while(*++p != '$')
			putchar(*p);
		putchar('\n');
	}
}

/*
 * When sending over TCP, nsnotifyd will handle only one message at a
 * time, but we want to ensure it does the right thing when we send
 * faster than that. But while we are sending, we also need to handle
 * replies to avoid filling up buffers and blocking. So here's a fun
 * little select() loop.
 */
static int
tcp_write(int s, const byte *msgv[], size_t msgc, int debug) {
	/* length followed by maximum message size */
	static byte rdbuf[2 + 0xffff];
	int r;

	r = fcntl(s, F_GETFL, 0);
	if(r < 0) {
		warn("fcntl(O_NONBLOCK)");
		return(-1);
	}
	r = fcntl(s, F_SETFL, r | O_NONBLOCK);
	if(r < 0) {
		warn("fcntl(O_NONBLOCK)");
		return(-1);
	}

	size_t wrmsg = 0, wrlen = 0, wrpos = 0;
	size_t rdmsg = 0, rdlen = 0, rdpos = 0;

	wrlen = ns_get16(msgv[wrmsg]);
	rdlen = 2;

	for(;;) {
		fd_set rdset; FD_ZERO(&rdset); FD_SET(s, &rdset);
		fd_set wrset; FD_ZERO(&wrset); FD_SET(s, &wrset);

		r = select(s + 1, &rdset, &wrset, NULL, NULL);
		if(r < 0 && errno == EINTR) continue;
		if(r < 0) {
			warn("select");
			return(-1);
		}

		if(FD_ISSET(s, &rdset)) {
			ssize_t n = read(s, rdbuf + rdpos, rdlen - rdpos);
			if(n < 0 && errno == EINTR) continue;
			if(n < 0 && errno == EAGAIN) continue;
			if(n < 0) {
				warn("read");
				return(-1);
			}
			rdpos += (size_t)n;
			if(debug)
				fprintf(stderr, "; R %zu %zi %zu/%zu\n",
					rdmsg, n, rdpos, rdlen);
			if(rdpos == 2) {
				rdlen = ns_get16(rdbuf);
			} else if(rdpos >= rdlen) {
				rdmsg += 1;
				rdpos = 0;
				rdlen = 2;
				if(rdmsg >= msgc)
					return(0);
			}
		}

		if(FD_ISSET(s, &wrset) && wrmsg < msgc) {
			ssize_t n = write(s, msgv[wrmsg] + wrpos, wrlen - wrpos);
			if(n < 0 && errno == EINTR) continue;
			if(n < 0 && errno == EAGAIN) continue;
			if(n < 0) {
				warn("write");
				return(-1);
			}
			wrpos += (size_t)n;
			if(debug)
				fprintf(stderr, "; W %zu %zi %zu/%zu\n",
					wrmsg, n, wrpos, wrlen);
			if(wrpos >= wrlen) {
				wrmsg += 1;
				wrpos = 0;
				if(wrmsg < msgc)
					wrlen = ns_get16(msgv[wrmsg]);
				else
					wrlen = 0;
			}
		}
	}
}

/*
 * When sending over UDP, there's no need to handle replies
 */
static int
udp_write(int s, const byte *msgv[], size_t msgc, int debug) {
	for(size_t msgi = 0; msgi < msgc; msgi++) {
		size_t len = ns_get16(msgv[msgi]);
		ssize_t r = write(s, msgv[msgi] + 2, len);
		if(debug)
			fprintf(stderr, "; W %zu %zi/%zu\n",
				msgi, r, len);
		if(r < 0) {
			warn("write");
			return(-1);
		}
	}
	return(0);
}

static int
notify(struct addrinfo *hints, struct addrinfo *sai,
       const char *target, const char *port,
       const byte *msgv[], size_t msgc, int debug) {

	struct addrinfo *ai0, *ai;
	int r = getaddrinfo(target, port, hints, &ai0);
	if(r != 0) {
		warnx("%s: %s", target, gai_strerror(r));
		return(-1);
	}
	for(ai = ai0; ai != NULL; ai = ai->ai_next) {
		if(debug) {
			char host[NI_MAXHOST], serv[NI_MAXSERV];
			int e = getnameinfo(ai->ai_addr, ai->ai_addrlen,
					    host, sizeof(host),
					    serv, sizeof(serv),
					    NI_NUMERICHOST | NI_NUMERICSERV);
			if(e == 0)
				fprintf(stderr, "; -> %s [%s#%s]\n",
					target, host, serv);
			else
				fprintf(stderr, "; -> %s [%s]\n",
					target, gai_strerror(e));
		}
		int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if(s < 0) {
			warn("socket");
			r |= -1;
			continue;
		}
		const char *f = NULL;
		if(sai != NULL && bind(s, sai->ai_addr, sai->ai_addrlen) < 0) {
			f = "bind";
		}
		if(f == NULL && connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			f = "connect";
		}
		if(f != NULL) {
			close(s);
			warn("%s", f);
			r |= -1;
			continue;
		}
		if(ai->ai_socktype == SOCK_STREAM)
			r |= tcp_write(s, msgv, msgc, debug);
		else
			r |= udp_write(s, msgv, msgc, debug);
		close(s);
	}
	freeaddrinfo(ai0);
	return(r);
}

static const byte *
make_a_message(const char *zone, int debug) {
	unsigned buf[NS_PACKETSZ / sizeof(unsigned)];
	HEADER *header = (void*)&buf;
	byte *msg = (void*)&buf;
	int msglen = res_mkquery(ns_o_query, zone, ns_c_in, ns_t_soa,
				 NULL, 0, NULL, msg, sizeof(buf));
	if(msglen < 0)
		errx(1, "could not make DNS NOTIFY message for %s", zone);
	header->opcode = ns_o_notify;
	header->rd = 0;
	if(debug > 1)
		res_pquery(&_res, msg, msglen, stderr);
	byte *tcpmsg = malloc((size_t)msglen + 2);
	if(tcpmsg == NULL)
		err(1, "could not make DNS NOTIFY message for %s", zone);
	ns_put16(msglen, tcpmsg);
	memcpy(tcpmsg + 2, msg, (size_t)msglen);
	return(tcpmsg);
}

static size_t
make_messages(const byte ***msgvp, const char *file, int debug) {
	FILE *fh = fopen(file, "r");
	if(fh == NULL)
		err(1, "open %s", file);

	size_t msgc = 0;
	size_t maxmsg = 16;
	const byte **msgv = malloc(sizeof(*msgv) * maxmsg);
	if(msgv == NULL)
		err(1, "malloc");

	char zone[NS_MAXDNAME];
	while(fgets(zone, sizeof(zone), fh) != NULL) {
		size_t len = strlen(zone);
		if(len > 0 && zone[len-1] == '\n')
			zone[--len] = '\0';
		msgv[msgc++] = make_a_message(zone, debug);
		if(msgc == maxmsg) {
			maxmsg *= 2;
			msgv = realloc(msgv, sizeof(*msgv) * maxmsg);
			if(msgv == NULL)
				err(1, "malloc");
		}
	}
	if(ferror(fh) || fclose(fh))
		err(1, "read %s", file);

	*msgvp = msgv;
	return(msgc);
}

static int
usage(void) {
	fprintf(stderr,
"usage:	nsnotify [-46dtV] [-s addr] [-p port] zone target...\n"
"	nsnotify [-46dtV] [-s addr] [-p port] -F zones target...\n"
"	nsnotify [-46dtV] [-s addr] [-p port] -f targets zones...\n"
"	nsnotify [-46dtV] [-s addr] [-p port] -F zones -f targets\n"
"	-4		send on IPv4 only\n"
"	-6		send on IPv6 only\n"
"	-d		debugging mode\n"
"			(use twice to print DNS messages)\n"
"	-F zones	read domain names from file instead of command line\n"
"	-f targets	read targets from file instead of command line\n"
"	-p port		send notifies to this port number\n"
"			(default 53)\n"
"	-s addr		source address and optional port\n"
"	-t		send notifies over TCP instead of UDP\n"
"	-V		print version information\n"
"	zone		the zone for which to send notifies\n"
"	targets		destination addresses of notify messages\n"
		);
	return(1);
}

int
main(int argc, char *argv[]) {
	const char *port = "domain";
	const char *targets_fn = NULL;
	const char *zones_fn = NULL;
	char *source = NULL;
	int protocol = SOCK_DGRAM;
	int family = PF_UNSPEC;
	int debug = 0;
	int r;

	while((r = getopt(argc, argv, "46dF:f:p:s:tV")) != -1)
		switch(r) {
		case('4'):
			family = PF_INET;
			continue;
		case('6'):
			family = PF_INET6;
			continue;
		case('d'):
			debug++;
			continue;
		case('F'):
			zones_fn = optarg;
			continue;
		case('f'):
			targets_fn = optarg;
			continue;
		case('p'):
			port = optarg;
			continue;
		case('s'):
			source = optarg;
			continue;
		case('t'):
			protocol = SOCK_STREAM;
			continue;
		case('V'):
			exit(version());
		default:
			exit(usage());
		}

	res_init();
	if(debug > 1) _res.options |= RES_DEBUG;

	argc -= optind;
	argv += optind;
	if(targets_fn == NULL && zones_fn == NULL && argc < 2)
		exit(usage());
	if(targets_fn != NULL && zones_fn == NULL && argc < 1)
		exit(usage());
	if(targets_fn == NULL && zones_fn != NULL && argc < 1)
		exit(usage());
	if(targets_fn != NULL && zones_fn != NULL && argc > 0)
		exit(usage());

	struct addrinfo hints, *sai = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = protocol;

	if(source != NULL) {
		hints.ai_flags = AI_PASSIVE;
		r = getaddrinfo(source, NULL, &hints, &sai);
		if(r != 0) {
			errx(1, "%s: %s", source, gai_strerror(r));
		}
		if(sai->ai_next != NULL) {
			errx(1, "%s: ambiguous source address", source);
		}
		if(debug) {
			char host[NI_MAXHOST], serv[NI_MAXSERV];
			int e = getnameinfo(sai->ai_addr, sai->ai_addrlen,
					    host, sizeof(host),
					    serv, sizeof(serv),
					    NI_NUMERICHOST | NI_NUMERICSERV);
			if(e == 0)
				fprintf(stderr, "; source %s#%s\n",
					host, serv);
			else
				fprintf(stderr, "; source %s: %s\n",
					source,	gai_strerror(e));
		}
		hints.ai_family = sai->ai_family;
		hints.ai_flags = 0;
	}

	const byte **msgv, *msg1;
	size_t msgc;
	if(zones_fn != NULL) {
		msgc = make_messages(&msgv, zones_fn, debug);
	} else if(targets_fn != NULL) {
		msgc = (size_t)argc;
		msgv = malloc(sizeof(*msgv) * msgc);
		if(msgv == NULL)
			err(1, "malloc");
		for(int i = 0; i < argc; i++)
			msgv[i] = make_a_message(argv[i], debug);
		argv += argc;
		argc = 0;
	} else {
		const char *zone = *argv++; argc--;
		msg1 = make_a_message(zone, debug);
		msgv = &msg1;
		msgc = 1;
	}

	r = 0;
	for(int i = 0; i < argc; i++)
		r |= notify(&hints, sai, argv[i], port, msgv, msgc, debug);

	if(targets_fn == NULL)
		exit(!!r);

	FILE *fh;
	if(strcmp(targets_fn, "-") == 0) {
		targets_fn = "stdin";
		fh = stdin;
	} else {
		fh = fopen(targets_fn, "r");
		if(fh == NULL)
			err(1, "open %s", targets_fn);
	}

	char target[NI_MAXHOST];
	while(fgets(target, sizeof(target), fh) != NULL) {
		size_t len = strlen(target);
		if(len > 0 && target[len-1] == '\n')
			target[--len] = '\0';
		r |= notify(&hints, sai, target, port, msgv, msgc, debug);
	}
	if(ferror(fh) || fclose(fh))
		err(1, "read %s", targets_fn);

	exit(!!r);
}
