#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <resolv.h>
#include <unistd.h>

typedef unsigned char byte;

static const char * const opcode[] = {
	"QUERY",    "1",        "2",        "3",
	"NOTIFY",   "UPDATE",   "6",        "7",
	"8",        "9",        "10",       "11",
	"12",       "13",       "14",       "15",
};

static void
usage(void) {
	fprintf(stderr, "usage: axfr2git [-46] [-a addr] -p port zone repo\n");
	exit(1);
}

static void
print_header(HEADER *h) {
	printf(";; id=%d opcode=%s rcode=%s\n", ntohs(h->id),
	    opcode[h->opcode], p_rcode(h->rcode));
	printf(";; qr=%d aa=%d tc=%d rd=%d ra=%d zz=%d ad=%d cd=%d\n",
	    h->qr, h->aa, h->tc, h->rd, h->ra, h->unused, h->ad, h->cd);
	printf(";; qdcount=%d ancount=%d nscount=%d arcount=%d\n",
	    ntohs(h->qdcount), ntohs(h->ancount),
	    ntohs(h->nscount), ntohs(h->arcount));
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
	int s = -1;

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
	if(s < 0)
		errx(1, "could not listen on %s/%s", addr, port);
	else
		printf(";; listening on %s/%s\n\n", hostbuf, servbuf);

	byte msg[NS_MAXMSG];
	char qname[NS_MAXDNAME];
	struct sockaddr_storage sa_buf;
	struct sockaddr *sa = (void *) &sa_buf;
	socklen_t sa_len;
	byte *eom;

	for(;;) {
		memset(msg, 0, sizeof(HEADER));
		sa_len = sizeof(sa_buf);
		r = recvfrom(s, msg, sizeof(msg), 0, sa, &sa_len);
		if(r < 0) {
			warn("recv");
			continue;
		}
		eom = msg + r;

		r = getnameinfo(sa, sa_len,
			hostbuf, sizeof(hostbuf),
			servbuf, sizeof(servbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);
		if(r) errx(1, "%s", gai_strerror(r));
		printf(";; client %s/%s\n", hostbuf, servbuf);

		HEADER *h = (void *) msg;
		byte *p = msg + sizeof(HEADER);

		if(eom < p || h->qdcount != htons(1))
			goto formerr;
		print_header(h);

		r = ns_name_uncompress(msg, eom, p, qname, sizeof(qname));
		if(r < 0)
			goto formerr;
		p += r;

		int qtype, qclass;
		NS_GET16(qtype, p);
		NS_GET16(qclass, p);
		printf("%s. %s %s ?\n", qname, p_class(qclass), p_type(qtype));

		if(h->opcode != ns_o_notify ||
		    qclass != ns_c_in || qtype != ns_t_soa ||
		    strcmp(qname, zone) != 0)
			goto refused;

		h->rcode = ns_r_noerror;

	reply:
		h->qr = 1;
		// echo opcode
		h->aa = 1;
		h->tc = 0;
		// echo rd
		h->ra = 0;
		h->unused = 0;
		h->ad = 0;
		// echo cd
		h->ancount = 0;
		h->nscount = 0;
		h->arcount = 0;
		print_header(h);
		r = sendto(s, msg, p - msg, 0, sa, sa_len);
		if(r < 0)
			warn("sendto %s/%s\n", hostbuf, servbuf);
		printf("\n");
		continue;
	formerr:
		h->rcode = ns_r_formerr;
		h->qdcount = 0;
		goto reply;
	refused:
		h->rcode = ns_r_refused;
		goto reply;
	}
}
