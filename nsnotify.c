/* nsnotify: send DNS NOTIFY messages to lots of targets
 *
 * Written by Tony Finch <dot@dotat.at> <fanf2@cam.ac.uk>
 * at Cambridge University Information Services.
 *
 * You may do anything with this. It has no warranty.
 * <http://creativecommons.org/publicdomain/zero/1.0/>
 */

#define _BSD_SOURCE
#define _XOPEN_SOURCE
#define BIND_8_COMPAT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/nameser.h>
#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <resolv.h>
#include <unistd.h>

#include "version.h"

static int
udpsend(int family, const char *addr, const char *port,
    int s4, int s6, u_char *msg, size_t msglen) {
	struct addrinfo hints, *ai0, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	int r = getaddrinfo(addr, port, &hints, &ai0);
	if(r) {
		warnx("%s: %s", addr, gai_strerror(r));
		return(-1);
	}
	for(ai = ai0; ai != NULL; ai = ai->ai_next) {
		int s = -1;
		if(ai->ai_family == AF_INET)
			s = s4;
		if(ai->ai_family == AF_INET6)
			s = s6;
		if(s == -1)
			continue;
		r = sendto(s, msg, msglen, 0,
		    ai->ai_addr, ai->ai_addrlen);
		if(r < 0) {
			warn("sendto %s", addr);
			return(-1);
		}
	}
	freeaddrinfo(ai0);
	return(0);
}

static const char what_ident[] =
    "@(#) $Program: nsnotify $\n"
    "@(#) $Version: " VERSION " $\n"
    "@(#) $Date:    " REVDATE " $\n"
    "@(#) $Author:  Tony Finch (dot@dotat.at) (fanf2@cam.ac.uk) $\n"
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
"	-f targets	read targets from file instead of command line\n"
"	-p port		send notifies to this port number\n"
"			(default 53)\n"
"	-V		print version information\n"
"	zone		the zone for which to send notifies\n"
"	targets		destinations of notify messages\n"
"			(may be command-line arguments\n"
"			 or read from stdin, one per line)\n"
		);
	exit(1);
}

int
main(int argc, char *argv[]) {
	const char *port = "domain";
	const char *file = NULL;
	int family = PF_UNSPEC;
	int debug = 0;
	int r, e;

	while((r = getopt(argc, argv, "46df:p:V")) != -1)
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
		case('f'):
			file = optarg;
			continue;
		case('p'):
			port = optarg;
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
	if(argc < 1)
		usage();
	if(file != NULL && argc > 1)
		usage();

	const char *zone = *argv++; argc--;

	u_char msg[512];
	int msglen = res_mkquery(ns_o_notify, zone, ns_c_in, ns_t_soa,
	    NULL, 0, NULL, msg, sizeof(msg));
	if(msglen < 0)
		errx(1, "could not make DNS NOTIFY message for %s", zone);
	((HEADER *)msg)->rd = 0;
	if(debug > 1)
		res_pquery(&_res, msg, msglen, stderr);

	int s4, s6;
	if(family == PF_INET6)
		s4 = -1;
	else {
		s4 = socket(PF_INET, SOCK_DGRAM, 0);
		if(s4 < 0)
			err(1, "socket (IPv4)");
	}
	if(family == PF_INET)
		s6 = -1;
	else {
		s6 = socket(PF_INET6, SOCK_DGRAM, 0);
		if(s6 < 0)
			err(1, "socket (IPv6)");
	}

	e = 0;

	for(int i = 0; i < argc; i++) {
		r = udpsend(family, argv[i], port, s4, s6, msg, msglen);
		if(r == 0 && debug)
			fprintf(stderr, "; -> %s\n", argv[i]);
		else
			e = 1;
	}

	if(file == NULL)
		exit(e);

	FILE *fh;
	if(strcmp(file, "-") == 0) {
		file = "stdin";
		fh = stdin;
	} else {
		fh = fopen(file, "r");
		if(fh == NULL)
			err(1, "open %s", file);
	}

	char addr[64];
	while(fgets(addr, sizeof(addr), fh) != NULL) {
		size_t len = strlen(addr);
		if(len > 0 && addr[len-1] == '\n')
			addr[--len] = '\0';
		r = udpsend(family, addr, port, s4, s6, msg, msglen);
		if(r == 0 && debug)
			fprintf(stderr, "; -> %s\n", addr);
		else
			e = 1;
	}
	if(ferror(fh) || fclose(fh))
		err(1, "read %s", file);
	exit(e);
}
