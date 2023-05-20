/* nsnotifyd: handle DNS NOTIFY messages by running a command
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
#include <time.h>
#include <unistd.h>

#define	log_emerg(...)   syslog(LOG_EMERG,   __VA_ARGS__)
#define	log_alert(...)   syslog(LOG_ALERT,   __VA_ARGS__)
#define	log_crit(...)    syslog(LOG_CRIT,    __VA_ARGS__)
#define	log_err(...)     syslog(LOG_ERR,     __VA_ARGS__)
#define	log_warning(...) syslog(LOG_WARNING, __VA_ARGS__)
#define	log_notice(...)  syslog(LOG_NOTICE,  __VA_ARGS__)
#define	log_info(...)    syslog(LOG_INFO,    __VA_ARGS__)
#define	log_debug(...)   syslog(LOG_DEBUG,   __VA_ARGS__)

#pragma GCC diagnostic ignored "-Wunknown-pragmas"

/* They should have used sockaddr_storage... */
typedef union res_sockaddr_union res_sockaddr_t;

typedef unsigned char byte;

#include "version.h"

static const char what_ident[] =
    "@(#) $Program: nsnotifyd $\n"
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

static bool quit;

static void
sigexit(int dummy) {
	(void)dummy;
	quit = true;
}

static bool timeout;

static void
sigalarm(int dummy) {
	(void)dummy;
	timeout = true;
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
	sa.sa_handler = sigalarm;
	sa.sa_flags = 0;
	r = sigaction(SIGALRM, &sa, NULL);
	if(r < 0) err(1, "sigaction(SIGALRM)");
}

static const char *
isotime(time_t t) {
	static char buf[] = "YYYY-MM-DD HH:MM:SS +ZZZZ";
	strftime(buf, sizeof(buf), "%F %T %z", localtime(&t));
	return(buf);
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
listen_sock(bool tcp, int family, const char *addr, const char *port) {
	struct addrinfo hints, *ai0, *ai;
	int r, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
	r = getaddrinfo(addr, port, &hints, &ai0);
	if(r) errx(1, "%s/%s: %s", addr, port, gai_strerror(r));

	for(ai = ai0; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if(s < 0) {
			warn("socket %s", ai_sockstr(ai));
			continue;
		}
		r = 1;
		if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(r)) < 0) {
			warn("setsockopt %s SO_REUSEADDR", ai_sockstr(ai));
			goto next;
		}
		if(bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			warn("bind %s", ai_sockstr(ai));
			goto next;
		}
		/* backlog value from Stevens, UNIX network programming */
		if(tcp && listen(s, 1024) < 0) {
			warn("listen %s", ai_sockstr(ai));
			goto next;
		}
		log_notice("listening on %s", ai_sockstr(ai));
		freeaddrinfo(ai0);
		return(s);
	next:	close(s);
	}
	errx(1, "could not listen on %s/%s", addr, port);
}

static int
tcp_read(int s, byte *buf, ssize_t len) {
	for(;;) {
		if(len < 0)
			return(errno = EINVAL);
		ssize_t n = read(s, buf, (size_t)len);
		if(n == 0 && len > 0) {
			return(errno = ENOTCONN);
		}
		if(n < 0 && errno == EINTR && timeout) {
			timeout = false;
			return(errno = ETIMEDOUT);
		}
		if(n < 0 && errno == EINTR && quit)
			return(errno = ECHILD);
		if(n < 0 && errno == EINTR)
			continue;
		if(n < 0)
			return(errno);
		buf += (size_t)n;
		len -= (size_t)n;
		if(len == 0)
			return(0);
	}
}

static int
tcp_write(int s, byte *buf, ssize_t len) {
	for(;;) {
		ssize_t n = write(s, buf, (size_t)len);
		if(n < 0)
			return(-1);
		buf += (size_t)n;
		len -= (size_t)n;
		if(len == 0)
			return(0);
	}
}

static void
res_server_name(int family, const char *name) {
	struct addrinfo hints, *ai0, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_DGRAM;
	int r = getaddrinfo(name, "domain", &hints, &ai0);
	if(r) errx(1, "%s: %s", name, gai_strerror(r));
	if(ai0 == NULL) errx(1, "%s not found", name);

	int n;
	for(n = 0, ai = ai0; ai != NULL; ai = ai->ai_next, n++)
		;
	res_sockaddr_t *addr = calloc((size_t)n, sizeof(*addr));
	if(addr == NULL) err(1, "malloc");

	for(n = 0, ai = ai0; ai != NULL; ai = ai->ai_next, n++) {
		memset(&addr[n], 0, sizeof(addr[n]));
		memcpy(&addr[n], ai->ai_addr, ai->ai_addrlen);
	}
	res_setservers(&_res, addr, n);
	freeaddrinfo(ai0);
}

static res_sockaddr_t *res_saved_servers;
static int res_saved_server_count;

static void
res_saveservers(void) {
	int n = res_getservers(&_res, NULL, 0);
	res_saved_servers = calloc((size_t)n, sizeof(res_sockaddr_t));
	if(res_saved_servers == NULL) err(1, "malloc");
	res_saved_server_count = res_getservers(&_res, res_saved_servers, n);
}

static void
res_resetservers(void) {
	res_setservers(&_res, res_saved_servers, res_saved_server_count);
}

/*
 * When doing a timed refresh: Switch to making recursive queries via
 * the default resolver. (We always need to do this so we can look up
 * the authoritative server by name.) Make non-recursive SOA queries
 * if an authoritative server was specified on the command line.
 */
static void
soa_server_name(int family, const char *name) {
	res_resetservers();
	_res.options |= RES_RECURSE;
	if(name != NULL) {
		res_server_name(family, name);
		_res.options &= (u_long)~RES_RECURSE;
	}
}

/*
 * In response to a notify: Make a non-recursive query using the
 * server that notified us. RFC 1996 paragraph 3.11.
 */
static void
soa_server_addr(struct sockaddr *sa, socklen_t sa_len) {
	res_sockaddr_t addr;
	memset(&addr, 0, sizeof(addr));
	memcpy(&addr, sa, sa_len);
	addr.sin.sin_port = htons(53);
	res_setservers(&_res, &addr, 1);
	_res.options &= (u_long)~RES_RECURSE;
}

/*
 * Sanity checking for SOA timing parameters.
 */
static uint32_t refresh_min = 1<<9;
static uint32_t refresh_max = 1<<15;
static uint32_t retry_min   = 1<<6;
static uint32_t retry_max   = 1<<12;
static uint32_t tcp_timeout = 1<<2;

static void
ttl_pair(char *str, uint32_t *min, uint32_t *max) {
	u_long ttl;
	char *sep = strchr(str, ':');
	if(sep != NULL)
		*sep++ = '\0';
	if(ns_parse_ttl(str, &ttl) < 0)
		errx(1, "invalid%s refresh time: %s",
		    sep != NULL ? " minimum" : "", str);
	*min = (uint32_t)ttl;
	if(sep == NULL) {
		*max = *min;
		return;
	}
	if(ns_parse_ttl(sep, &ttl) < 0)
		errx(1, "invalid maximum refresh time: %s", sep);
	*max = (uint32_t)ttl;
	return;
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
			n = z;
	if(n->name == NULL) return;
	log_debug("%s refresh at %s", n->name, isotime(n->refresh));
	uint32_t interval = (uint32_t)(n->refresh - time(NULL));
	if(interval > refresh_max) interval = refresh_max;
	alarm(interval);
}

static void
refresh_jitter(zone *z, uint32_t interval) {
	interval -= res_randomid() % (interval / 10);
	z->refresh = time(NULL) + interval;
}

static const char *
zone_soa(zone *z) {
	byte msg[NS_PACKETSZ];
	char name[NS_MAXDNAME];
	int len, r;

	len = res_query(z->name, ns_c_in, ns_t_soa, msg, sizeof(msg));
	if(len < 0) return(hstrerror(h_errno));
	// resolver has already sanity-checked the query section
	byte *eom = msg + len, *p = msg + sizeof(HEADER);
	r = dn_skipname(p, eom);
	p += r + 4; // qname qtype qclass
	HEADER *h = (void *) msg;
	for(int ancount = ntohs(h->ancount); ancount > 0; ancount--) {
		if(p >= eom) return("truncated reply");
		p += r = ns_name_uncompress(msg, eom, p, name, sizeof(name));
		if(r < 0) return("bad owner");
		if(eom - p < 10) return("truncated RR");
		uint16_t type, class, rdlength;
		uint32_t ttl;
		NS_GET16(type, p);
		NS_GET16(class, p);
		NS_GET32(ttl, p);
		NS_GET16(rdlength, p);
		(void)ttl;
		if(eom - p < rdlength) return("truncated RDATA");
		byte *eor = p + rdlength;
		if(strcmp(name, z->name) == 0 &&
		    class == ns_c_in && type == ns_t_soa) {
			p += r = dn_skipname(p, eor);
			if(r < 0) return("bad SOA MNAME");
			p += r = dn_skipname(p, eor);
			if(r < 0) return("bad SOA RNAME");
			if(eor - p < 12) return("truncated SOA timers");
			uint32_t refresh, retry;
			NS_GET32(z->serial, p);
			NS_GET32(refresh, p);
			NS_GET32(retry, p);
			if(refresh < refresh_min) refresh = refresh_min;
			if(refresh > refresh_max) refresh = refresh_max;
			if(retry < retry_min) retry = retry_min;
			if(retry > retry_max) retry = retry_max;
			refresh_jitter(z, refresh);
			z->retry = retry;
			return(NULL);
		}
		p = eor;
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
zone_retry(zone *z) {
	if(z->retry == 0) return;
	refresh_jitter(z, z->retry);
	log_debug("%s retry at %s", z->name, isotime(z->refresh));
}

static void
zone_refresh(zone *zp, const char *cmd, const char *master) {
	zone z = *zp; // only update *zp if the refresh succeeds
	const char *e = zone_soa(&z);
	if(e != NULL) {
		log_err("%s IN SOA ? %s", z.name, e);
		zone_retry(zp);
		return;
	}
	if(zp->serial == 0 && zp->refresh == 0 && zp->retry == 0) {
		log_info("%s IN SOA %d wildcard; running %s",
		    z.name, z.serial, cmd);
	} else if (serial_lt(zp->serial, z.serial)) {
		log_info("%s IN SOA %d updated; running %s",
		    z.name, z.serial, cmd);
	} else {
		log_info("%s IN SOA %d unchanged", z.name, z.serial);
		*zp = z; // refresh later
		return;
	}
	switch(fork()) {
	case(-1):
		log_err("fork: %m");
		zone_retry(zp);
		return;
	case(0):;
		char serial_buf[] = "4294967295";
		snprintf(serial_buf, sizeof(serial_buf), "%u", z.serial);
		const char *cmdv[] = {
			cmd,
			z.name,
			serial_buf,
			master,
			NULL
		};
		/* quietly cast away const, sigh */
		execvp(cmd, (char**)(void*)cmdv);
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
		else {
			*zp = z; // success
			return;
		}
		zone_retry(zp); // command failed
		return;
	}
}

static int
usage(void) {
	fprintf(stderr,
"usage: nsnotifyd [-46dV] [-l facility] [-P pidfile] [-u user]\n"
"		[-s addr] [-a addr] [-p port] command zone...\n"
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
"	-R min:max	limit SOA refresh times (default %d:%d)\n"
"	-r min:max	limit SOA retry times (default %d:%d)\n"
"	-s addr		authoritative server for refresh queries\n"
"	-T max		TCP read timeout (default %d)\n"
"	-t		accept NOTIFYs over TCP instead of UDP\n"
"	-u user		drop privileges to user\n"
"	-V		print version information\n"
"	-w		wildcard: accept notifies on any zone\n"
"	command		the command to run when a zone changes\n"
"	zone...		list of zones for which to accept notifies\n",
		refresh_min, refresh_max,
		retry_min, retry_max,
		tcp_timeout);
	return(1);
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
	bool wild = false;
	bool tcp = false;
	char *cmd = NULL;
	int debug = 0;

	while((r = getopt(argc, argv, "46a:dl:P:p:R:r:s:T:tu:Vw")) != -1)
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
		case('R'):
			ttl_pair(optarg, &refresh_min, &refresh_max);
			continue;
		case('r'):
			ttl_pair(optarg, &retry_min, &retry_max);
			continue;
		case('s'):
			authority = optarg;
			continue;
		case('T'): {
			u_long ttl;
			if(ns_parse_ttl(optarg, &ttl) < 0)
				errx(1, "invalid time: %s", optarg);
			tcp_timeout = (uint32_t)ttl;
		} continue;
		case('t'):
			tcp = true;
			continue;
		case('u'):
			user = optarg;
			continue;
		case('w'):
			wild = true;
			continue;
		case('V'):
			exit(version());
		default:
			exit(usage());
		}

	openlog(basename(argv[0]), debug ? LOG_PERROR : LOG_PID, facility);

	res_init();
	res_saveservers();
	if(debug > 1) _res.options |= RES_DEBUG;
	/* be impatient */
	_res.retrans = 3;
	_res.retry = 2;

	if(debug > 1) {
		log_debug("SOA refresh limits %lu < %lu",
		    (u_long)refresh_min, (u_long)refresh_max);
		log_debug("SOA retry limits %lu < %lu",
		    (u_long)retry_min, (u_long)retry_max);
	}

	argc -= optind;
	argv += optind;
	if(argc < 1 || (argc == 1 && !wild))
		exit(usage());

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

	soa_server_name(family, authority);
	zone *zones;
	zones = calloc((size_t)(argc + 1), sizeof(*zones));
	if(zones == NULL)
		err(1, "malloc");
	for(zone *z = zones; argc > 0; z++) {
		z->name = *argv++; argc--;
		char *end = strchr(z->name, '\0');
		char *dot = strrchr(z->name, '.');
		if(dot != NULL && dot != z->name && dot + 1 == end)
			*dot = '\0';
		else if(strcmp(z->name, "root") == 0)
			z->name = ".";
		const char *e = zone_soa(z);
		if(e != NULL) errx(1, "%s IN SOA: %s", z->name, e);
		log_info("%s IN SOA %u", z->name, z->serial);
	}

	res_resetservers();
	int s = listen_sock(tcp, family, addr, port);

	sigactions();

// don't complain about daemon() on Mac OS
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

	if(!debug && daemon(1, 0) < 0)
		err(1, "daemon");

#pragma clang diagnostic pop

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

	for(;;) {
		static byte msg[0xffff];
		char qname[NS_MAXDNAME];
		struct sockaddr_storage sa_buf;
		struct sockaddr *sa = (void *) &sa_buf;
		socklen_t sa_len;
		ssize_t len = 0;
		int t = -1;

		refresh_alarm(zones);
		if(tcp) {
			sa_len = sizeof(sa_buf);
			t = r = accept(s, sa, &sa_len);
			if(debug)
				log_info("connection from %s",
					 sockstr(sa, sa_len));
		} else {
			memset(msg, 0, sizeof(HEADER));
			sa_len = sizeof(sa_buf);
			len = recvfrom(s, msg, sizeof(msg), 0, sa, &sa_len);
			r = (int)len;
		}
		alarm(0);

		if(r < 0) {
			if(quit)
				break;
			if(errno != EINTR) {
				log_err("%s: %m", tcp ? "accept" : "recv");
				continue;
			}
			timeout = false;
			// keep refreshing until there is nothing to do
			soa_server_name(family, authority);
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

	more:
		if(tcp) {
			alarm(tcp_timeout);
			r = tcp_read(t, msg, 2);
			if(r == 0) {
				byte *p = msg;
				NS_GET16(len, p);
				r = tcp_read(t, msg, len);
			}
			alarm(0);
			if(r == ECHILD)
				break;
			if(r != 0) {
				if(r != ENOTCONN || debug > 0)
					log_err("disconnected %s: %m",
						 sockstr(sa, sa_len));
				close(t);
				continue;
			}
		}

		if(debug > 1) {
			log_debug("%s query length %ld",
				  sockstr(sa, sa_len), len);
			res_pquery(&_res, msg, (int)len, stderr);
		}
		byte *eom = msg + len;
		byte *p = msg + sizeof(HEADER);
		HEADER *h = (void *)msg;

		if(eom < p) goto formerr;
		if(h->qdcount != htons(1)) goto formerr;

		p += r = ns_name_uncompress(msg, eom, p, qname, sizeof(qname));
		if(r < 0 || eom - p < 4) goto formerr;

		uint16_t qtype, qclass;
		NS_GET16(qtype, p);
		NS_GET16(qclass, p);
		if(h->opcode != ns_o_notify ||
		    qclass != ns_c_in || qtype != ns_t_soa)
			goto refused;

		zone *z, wz = { .name = qname };
		for(z = zones; z->name != NULL; z++)
			if(strcmp(z->name, qname) == 0)
				break;
		if(z->name == NULL) {
			if(wild) z = &wz;
			else goto refused;
		}

		// TODO: call ns_verify() to check TSIG
		// however libbind's ns_verify only does HMAC MD5
		// so it needs some work...

		log_info("%s notify from %s", z->name, sockstr(sa, sa_len));
		soa_server_addr(sa, sa_len);
		zone_refresh(z, cmd, addrstr(sa, sa_len));

		// build the reply mostly by echoing the query up to
		// p, which points to the end of the part we parsed
		h->rcode = ns_r_noerror;
	reply:
		// echo id
		h->qr = 1;
		// echo opcode
		h->aa = 1;
		h->tc = 0;
		// echo rd
		h->ra = 0;
		h->unused = 0;
		h->ad = 0;
		// echo cd
		// echo qdcount
		h->ancount = 0;
		h->nscount = 0;
		h->arcount = 0;
		// TODO: call ns_sign() to add TSIG
		len = p - msg;
		if(debug > 1) {
			log_debug("%s reply length %ld",
				  sockstr(sa, sa_len), (long)len);
			res_pquery(&_res, msg, (int)len, stdout);
		}
		if(tcp) {
			byte msglen[2];
			p = msglen;
			NS_PUT16((uint16_t)len, p);
			if(tcp_write(t, msglen, 2) < 0 ||
			   tcp_write(t, msg, len) < 0) {
				log_err("write %s: %m", sockstr(sa, sa_len));
				close(t);
				if(quit) break;
			} else if(h->rcode == ns_r_formerr) {
				if(debug)
					log_info("disconnected %s",
						 sockstr(sa, sa_len));
				close(t);
			} else {
				goto more;
			}
		} else {
			len = sendto(s, msg, (size_t)len, 0, sa, sa_len);
			if(len < 0)
				log_err("sendto %s: %m", sockstr(sa, sa_len));
		}
		continue;
	formerr:
		log_info("%s formerr", sockstr(sa, sa_len));
		h->rcode = ns_r_formerr;
		h->qdcount = 0;
		goto reply;
	refused:
		log_info("%s refused %s %s %s", sockstr(sa, sa_len),
		       qname, p_class(qclass), p_type(qtype));
		h->rcode = ns_r_refused;
		goto reply;
	}

	log_notice("exiting");
	if(pidfile != NULL) unlink(pidfile);
	exit(0);
}
