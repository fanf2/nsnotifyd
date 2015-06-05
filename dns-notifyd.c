#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <err.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <unistd.h>

typedef unsigned char byte;

static const char * const opcode[] = {
	"QUERY",    "1",        "2",        "3",
	"NOTIFY",   "UPDATE",   "6",        "7",
	"8",        "9",        "10",       "11",
	"12",       "13",       "14",       "15",
};

static void
sigactions(void) {
	struct sigaction sa;
	int r;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	r = sigaction(SIGPIPE, &sa, NULL);
	if(r < 0) err(1, "sigaction(SIGPIPE)");
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

static uint32_t
soa_serial(const char *zone) {
	byte msg[NS_MAXMSG];
	char name[NS_MAXDNAME];
	int len, r;

	len = res_query(zone, ns_c_in, ns_t_soa, msg, sizeof(msg));
	if(len < 0)
		errx(1, "%s IN SOA: %s", zone, hstrerror(h_errno));
	byte *eom = msg + len, *p = msg + sizeof(HEADER);
	r = dn_skipname(p, eom);
	p += r + 4; // qname qtype qclass
	HEADER *h = (void *) msg;
	int type, class, ttl, rdlength, serial;
	for(int ancount = ntohs(h->ancount); ancount > 0; ancount--) {
		if(p >= eom)
			errx(1, "%s IN SOA: truncated reply", zone);
		r = ns_name_uncompress(msg, eom, p, name, sizeof(name));
		if(r < 0)
			errx(1, "%s IN SOA: bad owner", zone);
		p += r;
		if(eom - p < 10)
			errx(1, "%s IN SOA: truncated RR", zone);
		NS_GET16(type, p);
		NS_GET16(class, p);
		NS_GET32(ttl, p);
		NS_GET16(rdlength, p);
		if(eom - p < rdlength)
			errx(1, "%s IN SOA: truncated RDATA", zone);
		if(strcmp(name, zone) == 0 && class == ns_c_in && type == ns_t_soa) {
			r = dn_skipname(p, eom);
			if(r < 0) errx(1, "%s IN SOA: bad mname", zone);
			p += r;
			r = dn_skipname(p, eom);
			if(r < 0) errx(1, "%s IN SOA: bad rname", zone);
			p += r;
			NS_GET32(serial, p);
			return(serial);
		}
		p += rdlength;
	}
	errx(1, "%s IN SOA: missing answer", zone);
}

static bool
serial_lt(uint32_t s1, uint32_t s2) {
	int64_t i1 = s1, i2 = s2, smax = 0x80000000;
	return(s1 != s2 && (
		(i1 < i2 && i2 - i1 < smax) ||
		(i1 > i2 && i1 - i2 > smax) ));
}

static void
usage(void) {
	fprintf(stderr, "usage: dns-notifyd [-46] [-a addr] -p port zone command...\n");
	exit(1);
}

int
main(int argc, char *argv[]) {
	int r;
	int family = PF_UNSPEC;
	const char *addr = "127.0.0.1";
	const char *port = NULL;
	const char *zone;

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

	if(argc < 2 || addr == NULL || port == NULL)
		usage();

	zone = *argv++; argc--;

	uint32_t serial = soa_serial(zone);
	printf("%s. IN SOA (... %d ...)\n", zone, serial);

	sigactions();

	struct addrinfo hints, *res, *res0;
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	int s = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;
	r = getaddrinfo(addr, port, &hints, &res0);
	if(r) errx(1, "%s", gai_strerror(r));

	for(res = res0; res != NULL; res = res->ai_next) {
		r = getnameinfo(res->ai_addr, res->ai_addrlen,
			host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV);
		if(r) errx(1, "%s", gai_strerror(r));

		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if(s < 0) {
			warn("socket %s/%s", host, serv);
			continue;
		}
		if(bind(s, res->ai_addr, res->ai_addrlen) < 0) {
			warn("bind %s/%s", host, serv);
			continue;
		}
		break;
	}
	if(s < 0)
		errx(1, "could not listen on %s/%s", addr, port);
	else
		printf(";; listening on %s/%s\n\n", host, serv);

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
			host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV);
		if(r) errx(1, "%s", gai_strerror(r));
		printf(";; client %s/%s\n", host, serv);

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

		uint32_t newserial = soa_serial(zone);
		printf("%s. IN SOA (... %d ...)\n", zone, newserial);
		if(serial_lt(serial, newserial))
			switch(fork()) {
			case(-1):
				warn("fork");
				break;
			case(0):
				execvp(argv[0], argv);
				err(1, "exec %s", argv[0]);
			default:
				if(wait(&r) < 0)
					warn("wait");
				else if(!WIFEXITED(r))
					warnx("%s died with signal %d",
					    argv[0], WTERMSIG(r));
				else if(WEXITSTATUS(r) != 0)
					warnx("%s exited with status %d",
					    argv[0], WEXITSTATUS(r));
			}

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
			warn("sendto %s/%s\n", host, serv);
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
