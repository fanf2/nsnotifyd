#define _BSD_SOURCE
#define _XOPEN_SOURCE
#define BIND_8_COMPAT
#define SYSLOG_NAMES

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

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <err.h>
#include <grp.h>
#include <libgen.h>
#include <netdb.h>
#include <pwd.h>
#include <resolv.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#define	log_emerg(...)   syslog(LOG_EMERG,   __VA_ARGS__)
#define	log_alert(...)   syslog(LOG_ALERT,   __VA_ARGS__)
#define	log_crit(...)    syslog(LOG_CRIT,    __VA_ARGS__)
#define	log_err(...)     syslog(LOG_ERR,     __VA_ARGS__)
#define	log_warning(...) syslog(LOG_WARNING, __VA_ARGS__)
#define	log_notice(...)  syslog(LOG_NOTICE,  __VA_ARGS__)
#define	log_info(...)    syslog(LOG_INFO,    __VA_ARGS__)
#define	log_debug(...)   syslog(LOG_DEBUG,   __VA_ARGS__)

/* They should have used sockaddr_storage... */
typedef union res_sockaddr_union res_sockaddr_t;

typedef unsigned char byte;

static bool quit;

static void
sigexit(int sig) {
	write(2, "QUIT\n", 5);
	quit = sig;
}

static void
signoop(int sig) {
	sig = sig;
}

static void
sigactions(void) {
	struct sigaction sa;
	int r;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	r = sigaction(SIGPIPE, &sa, NULL);
	if(r < 0) err(1, "sigaction(SIGPIPE)");
	sa.sa_handler = sigexit;
	sa.sa_flags = 0;
	r = sigaction(SIGINT, &sa, NULL);
	if(r < 0) err(1, "sigaction(SIGINT)");
	r = sigaction(SIGTERM, &sa, NULL);
	if(r < 0) err(1, "sigaction(SIGTERM)");
	sa.sa_handler = signoop;
	sa.sa_flags = 0;
	r = sigaction(SIGALRM, &sa, NULL);
	if(r < 0) err(1, "sigaction(SIGALRM)");
}

static void
hostservstr(struct sockaddr *sa, socklen_t sa_len,
    char **host_r, char**serv_r) {
	static char host[NI_MAXHOST], serv[NI_MAXSERV];
	int r = getnameinfo(sa, sa_len,
			    host, sizeof(host), serv, sizeof(serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);
	if(r) errx(1, "getnameinfo: %s", gai_strerror(r));
	*host_r = host; *serv_r = serv;
}
static char *
addrstr(struct sockaddr *sa, socklen_t sa_len) {
	char *host, *serv;
	hostservstr(sa, sa_len, &host, &serv);
	return(host);
}
static const char *
sockstr(struct sockaddr *sa, socklen_t sa_len) {
	static char hostserv[NI_MAXHOST + NI_MAXSERV];
	char *host, *serv;
	hostservstr(sa, sa_len, &host, &serv);
	snprintf(hostserv, sizeof(hostserv), "%s/%s", host, serv);
	return(hostserv);
}
static const char *
ai_sockstr(struct addrinfo *ai) {
	return(sockstr(ai->ai_addr, ai->ai_addrlen));
}

static int
listen_udp(int family, const char *addr, const char *port) {
	struct addrinfo hints, *ai;
	int r, s;

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
		log_notice("listening on %s", ai_sockstr(ai));
		return(s);
	}
	errx(1, "could not listen on %s/%s", addr, port);
}

static void
res_server_name(const char *name) {
	struct addrinfo hints, *ai0, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_DGRAM;
	int r = getaddrinfo(name, "domain", &hints, &ai0);
	if(r) errx(1, "%s: %s", name, gai_strerror(r));

	int n;
	for(n = 0, ai = ai0; ai != NULL; ai = ai->ai_next, n++)
		;
	res_sockaddr_t addr[n];

	for(n = 0, ai = ai0; ai != NULL; ai = ai->ai_next, n++) {
		memset(&addr[n], 0, sizeof(addr[n]));
		memcpy(&addr[n], ai->ai_addr, ai->ai_addrlen);
	}
	res_setservers(&_res, addr, n);
}

static res_sockaddr_t *res_saved_servers;
static int res_saved_server_count;

static void
res_saveservers(void) {
	int n = res_getservers(&_res, NULL, 0);
	res_saved_servers = calloc(n, sizeof(res_sockaddr_t));
	if(res_saved_servers == NULL) err(1, "malloc");
	res_saved_server_count = res_getservers(&_res, res_saved_servers, n);
}

static void
res_resetservers(void) {
	res_setservers(&_res, res_saved_servers, res_saved_server_count);
}

/*
 * Make non-recursive SOA queries if an authoritative server was
 * specified on the command line, otherwise make recursive queries
 * to the default resolver.
 */
static void
soa_server_name(const char *name) {
	if(name == NULL) {
		res_resetservers();
		_res.options |= RES_RECURSE;
	} else {
		res_server_name(name);
		_res.options &= ~RES_RECURSE;
	}
}

/*
 * Make a non-recursive query using the server that notified us.
 * RFC 1996 paragraph 3.11.
 */
static void
soa_server_addr(struct sockaddr *sa, socklen_t sa_len) {
	res_sockaddr_t addr;
	memset(&addr, 0, sizeof(addr));
	memcpy(&addr, sa, sa_len);
	addr.sin.sin_port = htons(53);
	res_setservers(&_res, &addr, 1);
	_res.options &= ~RES_RECURSE;
}

typedef struct zone {
	const char *name;
	uint32_t serial, retry;
	time_t refresh;
} zone;

static void
refresh_alarm(zone z[]) {
	zone *n;
	for(n = z; z->name != NULL; z++)
		if(n->refresh > z->refresh)
			n->refresh = z->refresh;
	char buf[] = "YYYY-MM-DD HH:MM:SS +ZZZZ";
	strftime(buf, sizeof(buf), "%F %T %z", localtime(&n->refresh));
	log_debug("%s refresh at %s", n->name, buf);
	alarm(n->refresh - time(NULL));
}

static const char *
zone_soa(zone *z) {
	byte msg[NS_PACKETSZ];
	char name[NS_MAXDNAME];
	int len, r;

	len = res_query(z->name, ns_c_in, ns_t_soa, msg, sizeof(msg));
	if(len < 0) return(hstrerror(h_errno));
	byte *eom = msg + len, *p = msg + sizeof(HEADER);
	r = dn_skipname(p, eom);
	p += r + 4; // qname qtype qclass
	HEADER *h = (void *) msg;
	uint32_t type, class, ttl, rdlength;
	time_t now = time(NULL);
	for(int ancount = ntohs(h->ancount); ancount > 0; ancount--) {
		if(p >= eom) return("truncated reply");
		r = ns_name_uncompress(msg, eom, p, name, sizeof(name));
		if(r < 0) return("bad owner");
		p += r;
		if(eom - p < 10) return("truncated RR");
		NS_GET16(type, p);
		NS_GET16(class, p);
		NS_GET32(ttl, p); ttl = ttl;
		NS_GET16(rdlength, p);
		if(eom - p < rdlength) return("truncated RDATA");
		byte *eor = p + rdlength;
		if(strcmp(name, z->name) == 0 &&
		    class == ns_c_in && type == ns_t_soa) {
			r = dn_skipname(p, eor);
			if(r < 0) return("bad SOA MNAME");
			p += r;
			r = dn_skipname(p, eor);
			if(r < 0) return("bad SOA RNAME");
			p += r;
			if(eor - p < 12) return("truncated SOA timers");
			uint32_t interval;
			NS_GET32(z->serial, p);
			NS_GET32(interval, p);
			NS_GET32(z->retry, p);
			/* clamp timers for sanity */
			if(interval < 1<<9)  interval = 1<<9;
			if(interval > 1<<15) interval = 1<<15;
			if(z->retry < 1<<6)  z->retry = 1<<6;
			if(z->retry > 1<<12) z->retry = 1<<12;
			z->refresh = now + interval;
			return(NULL);
		}
		p += rdlength;
	}
	return("missing answer");
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
zone_refresh(zone *z, const char *cmd, const char *master) {
	char serial_buf[] = "4294967295";
	uint32_t oldserial = z->serial;
	const char *e = zone_soa(z);
	if(e != NULL) {
		log_err("%s IN SOA ? %s", z->name, e);
		return;
	}
	if(!serial_lt(oldserial, z->serial)) {
		log_info("%s IN SOA %d unchanged", z->name, z->serial);
		return;
	}
	log_info("%s IN SOA %d updated; running %s",
	    z->name, z->serial, cmd);
	switch(fork()) {
	case(-1):
		log_err("fork: %m");
		return;
	case(0):
		snprintf(serial_buf, sizeof(serial_buf), "%u", z->serial);
		const char *cmdv[] = {
			cmd,
			z->name,
			serial_buf,
			master,
			NULL
		};
		execvp(cmd, (char**)cmdv);
		err(1, "exec %s", cmd);
	default:;
		int r;
		if(wait(&r) < 0)
			log_err("wait: %m");
		else if(!WIFEXITED(r))
			log_err("%s died with signal %d",
			    cmd, WTERMSIG(r));
		else if(WEXITSTATUS(r) != 0)
			log_err("%s exited with status %d",
			    cmd, WEXITSTATUS(r));
		return;
	}
}

static void
usage(void) {
	fprintf(stderr,
"usage: nsnotifyd [-46d] [-l facility] [-P pidfile] [-u user]\n"
"		 [-a addr] [-p port] command zone...\n"
"	-4		listen on IPv4 only\n"
"	-6		listen on IPv6 only\n"
"	-a addr		listen on this IP address or host name\n"
"			(default 127.0.0.1)\n"
"	-d		debugging mode\n"
"			(use twice to print DNS messages)\n"
"	-l facility	syslog facility name\n"
"	-P pidfile	write daemon pid to this file\n"
"	-p port		listen on this port number or service name\n"
"			(default 53)\n"
"	-s addr		authoritative server for refresh queries\n"
"	-u user		drop privileges to user\n"
"	command		the command to run when a zone changes\n"
"	zone...		list of zones for which to accept notifies\n"
		);
	exit(1);
}

int
main(int argc, char *argv[]) {
	int r, i;
	int family = PF_UNSPEC;
	int facility = LOG_DAEMON;
	const char *pidfile = NULL;
	const char *user = NULL;
	const char *addr = "127.0.0.1";
	const char *port = "domain";
	const char *authority = NULL;
	char *cmd = NULL;
	int debug = false;

	while((r = getopt(argc, argv, "46a:dl:P:p:s:u:")) != -1)
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
		case('d'):
			debug++;
			continue;
		case('l'):
			for(i = 0; facilitynames[i].c_name != NULL; i++)
				if(strcmp(facilitynames[i].c_name, optarg) == 0)
					break;
			if(facilitynames[i].c_name == NULL)
				errx(1, "%s: Unknown syslog facility", optarg);
			facility = facilitynames[i].c_val;
			continue;
		case('P'):
			pidfile = optarg;
			continue;
		case('p'):
			port = optarg;
			continue;
		case('s'):
			authority = optarg;
			continue;
		case('u'):
			user = optarg;
			continue;
		default:
			usage();
		}

	openlog(basename(argv[0]), debug ? LOG_PERROR : LOG_PID, facility);

	res_init();
	res_saveservers();
	if(debug > 1) _res.options |= RES_DEBUG;
	/* be impatient */
	_res.retrans = 3;
	_res.retry = 2;

	argc -= optind;
	argv += optind;
	if(argc < 2 || addr == NULL || port == NULL)
		usage();

	cmd = *argv++; argc--;

	struct passwd *pw = NULL;
	if(user != NULL) {
		errno = 0;
		pw = getpwnam(user);
		if(pw == NULL && errno == 0)
			errx(1, "getpwnam %s: Unknown user", user);
		if(pw == NULL)
			err(1, "getpwnam %s", user);
	}

	int s = listen_udp(family, addr, port);

	zone zones[argc + 1];
	memset(&zones[argc], 0, sizeof(zone));

	soa_server_name(authority);
	for(zone *z = zones; argc > 0; z++) {
		memset(z, 0, sizeof(*z));
		z->name = *argv++; argc--;
		const char *e = zone_soa(z);
		if(e != NULL) errx(1, "%s IN SOA: %s", z->name, e);
		log_info("%s IN SOA %u", z->name, z->serial);
	}

	sigactions();

	if(!debug && daemon(1, 0) < 0)
		err(1, "daemon");

	if(pidfile != NULL) {
		FILE *fp = fopen(pidfile, "w");
		if(fp == NULL) {
			log_err("open %s: %m", pidfile);
		} else {
			fprintf(fp, "%d\n", getpid());
			fclose(fp);
		}
	}

	if(pw != NULL) {
		if(setgid(pw->pw_gid) < 0)
			log_err("setgid %s: %m", user);
		if(initgroups(pw->pw_name, pw->pw_gid) < 0)
			log_err("initgroups %s: %m", user);
		if(setuid(pw->pw_uid) < 0)
			log_err("setuid %s: %m", user);
	}

	byte msg[NS_PACKETSZ];
	char qname[NS_MAXDNAME];
	struct sockaddr_storage sa_buf;
	struct sockaddr *sa = (void *) &sa_buf;
	socklen_t sa_len;
	ssize_t len;
	byte *eom;

	for(;;) {
		refresh_alarm(zones);
		memset(msg, 0, sizeof(HEADER));
		sa_len = sizeof(sa_buf);
		len = recvfrom(s, msg, sizeof(msg), 0, sa, &sa_len);
		alarm(0);

		if(len < 0) {
			if(quit) {
				log_notice("exiting");
				if(pidfile != NULL) unlink(pidfile);
				exit(0);
			}
			if(errno != EINTR) {
				log_err("recv: %m");
				continue;
			}
			/* keep refreshing until there is nothing to do */
			soa_server_name(authority);
			bool refreshed = true;
			while(refreshed) {
				refreshed = false;
				time_t now = time(NULL);
				for(zone *z = zones; z->name != NULL; z++) {
					if(z->refresh > now)
						continue;
					log_info("%s refresh", z->name);
					zone_refresh(z, cmd, NULL);
					refreshed = true;
				}
			}
			continue;
		}
		if(debug > 1) {
			log_debug("%s query length %ld",
				  sockstr(sa, sa_len), len);
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
		    qclass != ns_c_in || qtype != ns_t_soa)
			goto refused;

		zone *z;
		for(z = zones; z->name != NULL; z++)
			if(strcmp(z->name, qname) == 0)
				break;
		if(z->name == NULL)
			goto refused;

		log_info("%s notify from %s", z->name, sockstr(sa, sa_len));
		soa_server_addr(sa, sa_len);
		zone_refresh(z, cmd, addrstr(sa, sa_len));

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
		if(debug > 1) {
			log_debug("%s reply length %ld",
				  sockstr(sa, sa_len), p - msg);
			res_pquery(&_res, msg, p - msg, stdout);
		}
		len = sendto(s, msg, p - msg, 0, sa, sa_len);
		if(len < 0)
			log_err("sendto %s: %m", sockstr(sa, sa_len));
		continue;
	formerr:
		log_info("%s formerr", sockstr(sa, sa_len));
		h->rcode = ns_r_formerr;
		h->qdcount = 0;
		goto reply;
	refused:
		log_info("%s %s. %s %s refused", sockstr(sa, sa_len),
		       qname, p_class(qclass), p_type(qtype));
		h->rcode = ns_r_refused;
		goto reply;
	}
}