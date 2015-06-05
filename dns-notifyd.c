#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>

#define BIND_8_COMPAT

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <err.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <unistd.h>

typedef unsigned char byte;

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

static const char *
sockstr(struct sockaddr *sa, socklen_t sa_len) {
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	static char hostserv[NI_MAXHOST + NI_MAXSERV];
	int r = getnameinfo(sa, sa_len,
			    host, sizeof(host), serv, sizeof(serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);
	if(r) errx(1, "getnameinfo: %s", gai_strerror(r));
	snprintf(hostserv, sizeof(hostserv), "%s/%s", host, serv);
	return(hostserv);
}
static const char *
ai_sockstr(struct addrinfo *ai) {
	return(sockstr(ai->ai_addr, ai->ai_addrlen));
}

static uint32_t
soa_serial(const char *zone) {
	byte msg[NS_PACKETSZ];
	char name[NS_MAXDNAME];
	int len, r;

	len = res_query(zone, ns_c_in, ns_t_soa, msg, sizeof(msg));
	if(len < 0)
		errx(1, "%s IN SOA: %s", zone, hstrerror(h_errno));
	byte *eom = msg + len, *p = msg + sizeof(HEADER);
	r = dn_skipname(p, eom);
	p += r + 4; // qname qtype qclass
	HEADER *h = (void *) msg;
	uint32_t type, class, ttl, rdlength, serial;
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

/* RFC 1982 */
static bool
serial_lt(uint32_t s1, uint32_t s2) {
	int64_t i1 = s1, i2 = s2, smax = 0x80000000;
	return(s1 != s2 && (
		(i1 < i2 && i2 - i1 < smax) ||
		(i1 > i2 && i1 - i2 > smax) ));
}

static void
usage(void) {
	fprintf(stderr,
"usage: dns-notifyd [-46d] [-a addr] [-p port] zone command...\n"
"	-4		listen on IPv4 only\n"
"	-6		listen on IPv6 only\n"
"	-d		debugging mode\n"
"	-a addr		listen on this IP address or host name\n"
"			(default 127.0.0.1)\n"
"	-p port		listen on this port number or service name\n"
"			(default 53)\n"
"	zone		the zone for which to accept notifies\n"
"	command...	the command to run when the zone changes\n"
		);
	exit(1);
}

int
main(int argc, char *argv[]) {
	int r;
	int family = PF_UNSPEC;
	const char *addr = "127.0.0.1";
	const char *port = "domain";
	const char *zone;
	bool debug = false;

	while((r = getopt(argc, argv, "46a:dp:")) != -1)
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

	res_init();
	if(debug) _res.options |= RES_DEBUG;

	uint32_t serial = soa_serial(zone);
	printf("%s. IN SOA (... %d ...)\n", zone, serial);

	sigactions();

	struct addrinfo hints, *ai;
	int s = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;
	r = getaddrinfo(addr, port, &hints, &ai);
	if(r) errx(1, "%s/%s: %s", addr, port, gai_strerror(r));

	for(; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if(s < 0) {
			warn("socket %s", ai_sockstr(ai));
			continue;
		}
		r = 1;
		if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(r)) < 0) {
			warn("setsockopt %s SO_REUSEADDR", ai_sockstr(ai));
			close(s);
			s = -1;
			continue;
		}
		if(bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			warn("bind %s", ai_sockstr(ai));
			close(s);
			s = -1;
			continue;
		}
		printf("Listening on %s\n", ai_sockstr(ai));
		break;
	}
	if(s < 0)
		errx(1, "could not listen on %s/%s", addr, port);

	byte msg[NS_PACKETSZ];
	char qname[NS_MAXDNAME];
	struct sockaddr_storage sa_buf;
	struct sockaddr *sa = (void *) &sa_buf;
	socklen_t sa_len;
	ssize_t len;
	byte *eom;

	for(;;) {
		memset(msg, 0, sizeof(HEADER));
		sa_len = sizeof(sa_buf);
		len = recvfrom(s, msg, sizeof(msg), 0, sa, &sa_len);
		if(len < 0) {
			warn("recv");
			continue;
		}
		if(debug) {
			printf(";; client %s\n", sockstr(sa, sa_len));
			printf(";; message legnth %d\n", r);
			res_pquery(&_res, msg, len, stderr);
		}
		eom = msg + len;

		HEADER *h = (void *) msg;
		byte *p = msg + sizeof(HEADER);

		if(eom < p || h->qdcount != htons(1))
			goto formerr;

		r = ns_name_uncompress(msg, eom, p, qname, sizeof(qname));
		if(r < 0)
			goto formerr;
		p += r;

		int qtype, qclass;
		NS_GET16(qtype, p);
		NS_GET16(qclass, p);

		if(h->opcode != ns_o_notify ||
		    qclass != ns_c_in || qtype != ns_t_soa ||
		    strcmp(qname, zone) != 0)
			goto refused;

		/* Make a non-recursive query using the server that
		   notified us - RFC 1996 paragraph 3.11. */
		_res.options &= ~RES_RECURSE;
		union res_sockaddr_union res_addr;
		memcpy(&res_addr, sa, sa_len);
		res_addr.sin.sin_port = htons(53);
		res_setservers(&_res, &res_addr, 1);
		uint32_t newserial = soa_serial(zone);
		printf("%s %s. IN SOA (... %d ...)\n",
		       sockstr(sa, sa_len), zone, newserial);

		if(serial_lt(serial, newserial)) {
			printf("running %s\n", argv[0]);
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
		if(debug)
			res_pquery(&_res, msg, p - msg, stdout);
		len = sendto(s, msg, p - msg, 0, sa, sa_len);
		if(len < 0)
			warn("sendto %s\n", sockstr(sa, sa_len));
		continue;
	formerr:
		printf("%s formerr\n", sockstr(sa, sa_len));
		h->rcode = ns_r_formerr;
		h->qdcount = 0;
		goto reply;
	refused:
		printf("%s %s. %s %s refused\n", sockstr(sa, sa_len),
		       qname, p_class(qclass), p_type(qtype));
		h->rcode = ns_r_refused;
		goto reply;
	}
}
