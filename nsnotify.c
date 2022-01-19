/* nsnotify: send DNS NOTIFY messages to lots of targets
 *
 * Written by Tony Finch <dot@dotat.at>
 * at Cambridge University Information Services.
 *
 * You may do anything with this. It has no warranty.
 * <http://creativecommons.org/publicdomain/zero/1.0/>
 */

#define _BSD_SOURCE
#define _XOPEN_SOURCE
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

static void
version(void) {
	const char *p = what_ident;
	for(;;) {
		while(*++p != '$')
			if(*p == '\0')
				exit(0);
		while(*++p != '$')
			putchar(*p);
		putchar('\n');
	}
}

static void
usage(void) {
	fprintf(stderr,
"usage: nsnotify [-46dpV] [-f targets] zone [targets]\n"
"	-4		send on IPv4 only\n"
"	-6		send on IPv6 only\n"
"	-d		debugging mode\n"
"			(use twice to print DNS messages)\n"
"	-f zones	read domain names from file instead of command line\n"
"	-f targets	read targets from file instead of command line\n"
"	-p port		send notifies to this port number\n"
"			(default 53)\n"
"	-t		send notifies over TCP instead of UDP\n"
"	-V		print version information\n"
"	zone		the zone for which to send notifies\n"
"	targets		destinations of notify messages\n"
"			(may be command-line arguments\n"
"			 or read from stdin, one per line)\n"
		);
	exit(1);
}

/*
 * When sending over TCP, nsnotifyd will handle only one message at a
 * time, but we want to ensure it does the right thing when we send
 * faster than that. But while we are sending, we also need to handle
 * replies to avoid filling up buffers and blocking. So here's a fun
 * little select() loop.
 */
static int
tcp_write(int s, const byte *msgv[], size_t msgc) {
	static byte rdbuf[1 << 16];
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

	wrlen = msgv[wrmsg][0]*256 +
		msgv[wrmsg][1] + 2;
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
			if(rdpos == 2) {
				rdlen = rdbuf[0]*256 +
					rdbuf[1] + 2;
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
			wrpos += (size_t)r;
			if(wrpos >= wrlen) {
				wrmsg += 1;
				wrpos = 0;
				if(wrmsg < msgc)
					wrlen = msgv[wrmsg][0]*256 +
						msgv[wrmsg][1] + 2;
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
udp_write(int s, const byte *msgv[], size_t msgc) {
	for(size_t msgi = 0; msgi < msgc; msgi++) {
		size_t len = msgv[msgi][0]*256
			+ msgv[msgi][1];
		ssize_t r = write(s, msgv[msgi] + 2, len);
		if(r < 0) {
			warn("write");
			return(-1);
		}
	}
	return(0);
}

static int
notify(const char *target, const char *port, int family, int protocol,
       const byte *msgv[], size_t msgc, int debug) {

	struct addrinfo hints, *ai0, *ai;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = protocol;
	int r = getaddrinfo(target, port, &hints, &ai0);
	if(r != 0) {
		warnx("%s: %s", target, gai_strerror(r));
		return(-1);
	}
	for(ai = ai0; ai != NULL; ai = ai->ai_next) {
		if(ai->ai_family != family && family != PF_UNSPEC)
			continue;
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
		int s = socket(ai->ai_family, protocol, 0);
		if(s < 0) {
			warn("socket");
			r |= s;
			continue;
		}
		int e = connect(s, ai->ai_addr, ai->ai_addrlen);
		if(e < 0) {
			close(s);
			warn("connect");
			r |= e;
			continue;
		}
		if(protocol == SOCK_STREAM)
			r |= tcp_write(s, msgv, msgc);
		else
			r |= udp_write(s, msgv, msgc);
		close(s);
	}
	freeaddrinfo(ai0);
	return(r);
}

static const byte *
make_a_message(const char *zone, int debug) {
	byte msg[512];
	int msglen = res_mkquery(ns_o_notify, zone, ns_c_in, ns_t_soa,
				 NULL, 0, NULL, msg, sizeof(msg));
	if(msglen < 0)
		errx(1, "could not make DNS NOTIFY message for %s", zone);
	((HEADER *)msg)->rd = 0;
	if(debug > 1)
		res_pquery(&_res, msg, msglen, stderr);
	byte *tcpmsg = malloc((size_t)msglen + 2);
	if(tcpmsg == NULL)
		err(1, "could not make DNS NOTIFY message for %s", zone);
	tcpmsg[0] = (msglen & 0xff00) >> 8;
	tcpmsg[1] = (msglen & 0xff);
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

	char zone[256];
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

int
main(int argc, char *argv[]) {
	const char *port = "domain";
	const char *targets_fn = NULL;
	const char *zones_fn = NULL;
	int protocol = SOCK_DGRAM;
	int family = PF_UNSPEC;
	int debug = 0;
	int r;

	while((r = getopt(argc, argv, "46dF:f:p:tV")) != -1)
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
		case('t'):
			protocol = SOCK_STREAM;
			continue;
		case('V'):
			version();
		default:
			usage();
		}

	res_init();
	if(debug > 1) _res.options |= RES_DEBUG;

	argc -= optind;
	argv += optind;
	if(targets_fn == NULL && zones_fn == NULL && argc < 2)
		usage();
	if(targets_fn != NULL && zones_fn == NULL && argc < 1)
		usage();
	if(targets_fn == NULL && zones_fn != NULL && argc < 1)
		usage();
	if(targets_fn != NULL && zones_fn != NULL && argc > 0)
		usage();

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
		r |= notify(argv[i], port, family, protocol, msgv, msgc, debug);

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
		r |= notify(target, port, family, protocol, msgv, msgc, debug);
	}
	if(ferror(fh) || fclose(fh))
		err(1, "read %s", targets_fn);

	exit(!!r);
}
