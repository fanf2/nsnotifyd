#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <err.h>
#include <netdb.h>
#include <unistd.h>

static void
usage(void) {
	fprintf(stderr, "usage: axfr2git [-46] [-a addr] -p port zone repo\n");
	exit(1);
}

int
main(int argc, char *argv[]) {
	int r;
	int family = PF_UNSPEC;
	const char *addr = "127.0.0.1";
	const char *port = NULL;
	const char *zone, *repo;

	while((r = getopt(argc, argv, "46a:p:")) != -1)
		switch(r) {
		case('4'):
			family = PF_INET;
			continue;
		case('6'):
			family = PF_INET6;
			continue;
		case('a'):
			addr = optarg;
			continue;
		case('p'):
			port = optarg;
			continue;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if(argc != 2 || addr == NULL || port == NULL)
		usage();

	zone = argv[0];
	repo = argv[1];

	struct stat st;
	if(chdir(repo))
		err(1, "chdir %s", repo);
	if(stat(".git", &st) < 0)
		err(1, "stat %s/.git", repo);

	struct addrinfo hints, *res, *res0;
	char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
	int s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;
	r = getaddrinfo(addr, port, &hints, &res0);
	if(r) errx(1, "%s", gai_strerror(r));

	for(res = res0; res != NULL; res = res->ai_next) {
		r = getnameinfo(res->ai_addr, res->ai_addrlen,
			hostbuf, sizeof(hostbuf),
			servbuf, sizeof(servbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);
		if(r) errx(1, "%s", gai_strerror(r));

		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if(s < 0) {
			warn("socket %s/%s", hostbuf, servbuf);
			continue;
		}
		if(bind(s, res->ai_addr, res->ai_addrlen) < 0) {
			warn("bind %s/%s", hostbuf, servbuf);
			continue;
		}
		break;
	}
	warnx("listening on %s/%s", hostbuf, servbuf);

	exit(0);
}
