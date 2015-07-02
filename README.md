nsnotifyd: handle DNS NOTIFY messages by running a command
----------------------------------------------------------

The `nsnotifyd` daemon monitors a set of DNS zones and runs a command
when any of them change. It listens for DNS NOTIFY messages so it can
respond to changes promptly. It also uses each zone's SOA refresh and
retry parameters to poll for updates if `nsnotifyd` does not receive
NOTIFY messages more frequently.

Anywhere you currently have a cron job which is monitoring updates to
DNS zones, you might want to run it under `nsnotifyd` instead of cron,
so your script runs as soon as the zone changes instead of running at
fixed intervals.

### Examples

There are three example scripts described in the manual:

`nsnotify2git` records the history of changes to a set of zones.

`nsnotify2update` uses nsdiff and nsupdate as part of a bump-in-the-wire
DNSSEC signer.

`nsnotify2stealth` uses nsnotify-liststealth and nsnotify-fanout to
notify stealth secondaries so they get updates faster.

### Documentation

To read the manual, run

        $ man ./nsnotifyd.1

or read online in [plain text](http://dotat.at/prog/nsnotifyd/nsnotifyd.txt)
or [PDF](http://dotat.at/prog/nsnotifyd/nsnotifyd.pdf) formats.

The `nsnotifyd` homepage is <http://dotat.at/prog/nsnotifyd/>

### Build

To build, type

        $ ./configure
        $ make all

### Dependencies

The main requirement is the BIND-8 libc resolver. BSD and Mac OS ship
with a sufficiently recent resolver. On a Debian-like Linux you should
install libbind4-dev. Otherwise, the configure script will download
libbind and build and link with it statically.

### Latest release

Download the full source archives:

* <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.1.tar.xz>
* <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.1.tar.gz>
* <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.1.zip>

### Source repositories

You can clone or browse the repository from:

* git://dotat.at/nsnotifyd.git
* <http://dotat.at/cgi/git/nsnotifyd.git>
* <https://github.com/fanf2/nsnotifyd.git>
* <https://git.csx.cam.ac.uk/x/ucs/ipreg/nsnotifyd.git>

----------------------------------------------------------------

Please send bug reports or patches to me. I accept contributions made
under the terms of CC0. Thanks to JP Mens and Richard James Salts for
helpful feedback and encouragement.

Written by Tony Finch <dot@dotat.at> <fanf2@cam.ac.uk>  
at Cambridge University Information Services.

You may do anything with this. It has no warranty.  
<http://creativecommons.org/publicdomain/zero/1.0/>
