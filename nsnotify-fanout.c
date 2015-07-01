/* nsnotify-fanout: send DNS NOTIFY messages to lots of clients
 *
 * Written by Tony Finch <dot@dotat.at> <fanf2@cam.ac.uk>
 * at Cambridge University Information Services.
 *
 * You may do anything with this. It has no warranty.
 * <http://creativecommons.org/publicdomain/zero/1.0/>
 */

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

static const char what_ident[] =
    "@(#) $Program: nsnotify-fanout $\n"
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
"usage: nsnotify-fanout [-46dV] zone <clients\n"
"	-4		listen on IPv4 only\n"
"	-6		listen on IPv6 only\n"
"	-d		debugging mode\n"
"			(use twice to print DNS messages)\n"
"	-V		print version information\n"
"	zone		the zone for which to send notifies\n"
"	clients		one client address per line\n"
		);
	exit(1);
}

int
main(int argc, char *argv[]) {
	int family = PF_UNSPEC;
	int debug = 0;
	int r;

	while((r = getopt(argc, argv, "46dV")) != -1)
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
		case('V'):
			version();
		default:
			usage();
		}

	res_init();
	if(debug > 1) _res.options |= RES_DEBUG;

	argc -= optind;
	argv += optind;
	if(argc != 1)
		usage();

	const char *zone = argv[0];

	u_char msg[512];
	int msglen = res_mkquery(ns_o_notify, zone, ns_c_in, ns_t_soa,
	    NULL, 0, NULL, msg, sizeof(msg));
	if(msglen < 0)
		errx(1, "could not make DNS NOTIFY message for %s", zone);
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

	char addr[64];
	while(fgets(addr, sizeof(addr), stdin) != NULL) {
		size_t len = strlen(addr);
		if(len > 0 && addr[len-1] == '\n')
			addr[--len] = '\0';

		struct addrinfo hints, *ai0, *ai;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = family;
		hints.ai_socktype = SOCK_DGRAM;
		r = getaddrinfo(addr, "domain", &hints, &ai0);
		if(r) {
			warnx("%s: %s", addr, gai_strerror(r));
			continue;
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
			if(r < 0)
				warn("sendto %s", addr);
			else if(debug)
				fprintf(stderr, "; -> %s\n", addr);
		}
		freeaddrinfo(ai0);
	}
	if(ferror(stdin) || fclose(stdin))
		err(1, "read %s", zone);
	exit(0);
}
