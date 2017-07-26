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

There is also a client program `nsnotify` for sending notify messages.

### Examples

There are four example scripts described in the manual:

`metazone` allows you to use standard DNS mechanisms - AXFR, IXFR,
NOTIFY, UPDATE - to control the configuration of multiple name
servers, instead of using a separate out-of-band distribution system.

`nsnotify2git` records the history of changes to a set of zones.

`nsnotify2stealth` uses nsnotify-liststealth and nsnotify to
notify stealth secondaries so they get updates faster.

`nsnotify2update` uses nsdiff and nsupdate as part of a bump-in-the-wire
DNSSEC signer.

### Documentation

To read the `nsnotifyd` manual, run

        $ man ./nsnotifyd.1

or read online in [plain text](http://dotat.at/prog/nsnotifyd/nsnotifyd.1.txt)
or [PDF](http://dotat.at/prog/nsnotifyd/nsnotifyd.1.pdf) formats.

There are separate man pages for `nsnotify`
in [plain text](http://dotat.at/prog/nsnotifyd/nsnotify.1.txt)
or [PDF](http://dotat.at/prog/nsnotifyd/nsnotify.1.pdf),
the `metazone` script
in [plain text](http://dotat.at/prog/nsnotifyd/metazone.1.txt)
or [PDF](http://dotat.at/prog/nsnotifyd/metazone.1.pdf)
and the `metazone` format
in [plain text](http://dotat.at/prog/nsnotifyd/metazone.5.txt)
or [PDF](http://dotat.at/prog/nsnotifyd/metazone.5.pdf).

The `nsnotifyd` homepage is <http://dotat.at/prog/nsnotifyd/>

### Build and install

To install in your home directory,

        $ ./configure
        $ make all
        $ make install

See the top of the Makefile for variables that control the install
location, for example,

        $ sudo make prefix=/usr/local install

You need to use GNU make to build the preformatted documentation.

[On FreeBSD, use the `nsnotifyd` port or package](https://www.freshports.org/dns/nsnotifyd/)

### Dependencies

The main requirement is the BIND-8 libc resolver. BSD and Mac OS ship
with a sufficiently recent resolver. On a Debian-like Linux you should
`apt install libbind4-dev`. Otherwise, the configure script will download
libbind and build and link with it statically.

### Latest release

Download the full source archives:

* <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.6.tar.xz>
* <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.6.tar.gz>
* <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.6.zip>

(Do not use GitHub's "Download ZIP" feature because it gives you
a broken partial copy that contains neither dev support files nor
release build output files.)

### Source repositories

You can clone or browse the repository from:

* git://dotat.at/nsnotifyd.git
* <http://dotat.at/cgi/git/nsnotifyd.git>
* <https://github.com/fanf2/nsnotifyd.git>
* <https://git.csx.cam.ac.uk/x/ucs/ipreg/nsnotifyd.git>

### Articles about nsnotifyd

* <http://fanf.livejournal.com/134988.html> nsnotifyd-1.0 announcement
* <http://fanf.livejournal.com/135257.html> nsnotifyd-1.1 announcement
* <http://jpmens.net/2015/06/16/alert-on-dns-notify/> review by JP Mens

And in other media...

* [TechSNAP 329: teeny weeny DNS server](http://www.jupiterbroadcasting.com/116921/teeny-weeny-dns-server-techsnap-329/) -
  video review by Dan Langille

----------------------------------------------------------------

Please send bug reports or patches to me. I accept contributions made
under the terms of CC0. Thanks to JP Mens, Gavin Brown, and Richard
James Salts for helpful feedback and encouragement.

Written by Tony Finch <dot@dotat.at> <fanf2@cam.ac.uk>  
at Cambridge University Information Services.

You may do anything with this. It has no warranty.  
<http://creativecommons.org/publicdomain/zero/1.0/>
