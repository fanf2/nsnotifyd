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

typedef unsigned char byte;

static bool quit;

static void
sigexit(int sig) {
	quit = sig;
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

static const char *
soa_serial(const char *zone, uint32_t *serial) {
	byte msg[NS_PACKETSZ];
	char name[NS_MAXDNAME];
	int len, r;

	len = res_query(zone, ns_c_in, ns_t_soa, msg, sizeof(msg));
	if(len < 0) return(hstrerror(h_errno));
	byte *eom = msg + len, *p = msg + sizeof(HEADER);
	r = dn_skipname(p, eom);
	p += r + 4; // qname qtype qclass
	HEADER *h = (void *) msg;
	uint32_t type, class, ttl, rdlength;
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
		if(strcmp(name, zone) == 0 && class == ns_c_in && type == ns_t_soa) {
			r = dn_skipname(p, eom);
			if(r < 0) return("bad SOA MNAME");
			p += r;
			r = dn_skipname(p, eom);
			if(r < 0) return("bad SOA RNAME");
			p += r;
			NS_GET32(*serial, p);
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
"	-S		do not check SOA at startup\n"
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
	bool checksoa = true;
	int debug = false;

	while((r = getopt(argc, argv, "46a:dl:P:p:Su:")) != -1)
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
		case('S'):
			checksoa = false;
			continue;
		case('u'):
			user = optarg;
			continue;
		default:
			usage();
		}

	openlog(basename(argv[0]), debug ? LOG_PERROR : LOG_PID, facility);

	res_init();
	if(debug > 1) _res.options |= RES_DEBUG;
	_res.retrans = 3;
	_res.retry = 2;

	argc -= optind;
	argv += optind;
	if(argc < 2 || addr == NULL || port == NULL)
		usage();

	uint32_t args[argc], serial;
	char serial_buf[] = "4294967295";
	char *cmdv[] = {
		*argv++,
		"zone",
		serial_buf,
		"master",
		NULL
	};

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

	for(int z = 0; argv[z] != NULL; z++) {
		if(checksoa) {
			const char *e = soa_serial(argv[z], &args[z]);
			if(e != NULL) errx(1, "%s IN SOA: %s", argv[z], e);
			log_info("%s IN SOA %u", argv[z], args[z]);
		} else {
			args[z] = 0; // buggy!
		}
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
		memset(msg, 0, sizeof(HEADER));
		sa_len = sizeof(sa_buf);
		len = recvfrom(s, msg, sizeof(msg), 0, sa, &sa_len);
		if(len < 0) {
			if(quit) {
				log_notice("exiting");
				if(pidfile != NULL) unlink(pidfile);
				exit(0);
			}
			log_err("recv: %m");
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

		int qtype, qclass, z;
		NS_GET16(qtype, p);
		NS_GET16(qclass, p);
		if(h->opcode != ns_o_notify ||
		    qclass != ns_c_in || qtype != ns_t_soa)
			goto refused;
		for(z = 0; argv[z] != NULL; z++)
			if(strcmp(argv[z], qname) == 0)
				break;
		if(argv[z] == NULL)
			goto refused;

		/* Make a non-recursive query using the server that
		   notified us - RFC 1996 paragraph 3.11. */
		_res.options &= ~RES_RECURSE;
		union res_sockaddr_union res_addr;
		memcpy(&res_addr, sa, sa_len);
		res_addr.sin.sin_port = htons(53);
		res_setservers(&_res, &res_addr, 1);
		const char *e = soa_serial(qname, &serial);
		if(e != NULL) {
			log_err("%s %s IN SOA ? %s",
				sockstr(sa, sa_len), qname, e);
		} else if(!serial_lt(args[z], serial)) {
			log_info("%s %s IN SOA %d unchanged",
				 sockstr(sa, sa_len), qname, serial);
		} else {
			log_info("%s %s IN SOA %d updated; running %s",
				 sockstr(sa, sa_len), qname, serial, cmdv[0]);
			args[z] = serial;
			switch(fork()) {
			case(-1):
				log_err("fork: %m");
				break;
			case(0):
				snprintf(serial_buf, sizeof(serial_buf), "%u", serial);
				cmdv[1] = qname;
				cmdv[2] = serial_buf;
				cmdv[3] = addrstr(sa, sa_len);
				execvp(cmdv[0], cmdv);
				err(1, "exec %s", cmdv[0]);
			default:
				if(wait(&r) < 0)
					log_err("wait: %m");
				else if(!WIFEXITED(r))
					log_err("%s died with signal %d",
					    argv[0], WTERMSIG(r));
				else if(WEXITSTATUS(r) != 0)
					log_err("%s exited with status %d",
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
