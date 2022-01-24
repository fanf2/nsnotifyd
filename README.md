nsnotifyd: scripted DNS NOTIFY handler
======================================

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

The 2.0 release (January 2022) adds TCP support to `nsnotifyd` and `nsnotify`
(for interoperability with [Knot DNS](https://www.knot-dns.cz/)),
and `nsnotify` can now rapidly send notifications for multiple zones.
Many thanks to [DK Hostmaster](https://www.dk-hostmaster.dk/)
for sponsoring this work.


Examples
--------

There are four example scripts described in the manual:

`metazone` allows you to use standard DNS mechanisms - AXFR, IXFR,
NOTIFY, UPDATE - to control the configuration of multiple name
servers, instead of using a separate out-of-band distribution system.

`nsnotify2git` records the history of changes to a set of zones.

`nsnotify2stealth` uses nsnotify-liststealth and nsnotify to
notify stealth secondaries so they get updates faster.

`nsnotify2update` uses nsdiff and nsupdate as part of a bump-in-the-wire
DNSSEC signer.


Documentation
-------------

To read the `nsnotifyd` manual, run

        $ man ./nsnotifyd.1

There are an HTML versions of the manual pages:

  * [nsnotifyd.1](html/nsnotifyd.1.html), the daemon
  * [nsnotify.1](html/nsnotify.1.html), the notifier
  * [metazone.1](html/metazone.1.html), the `metazone` example script
  * [metazone.5](html/metazone.5.html), the `metazone` file format

The `nsnotifyd` homepage is <http://dotat.at/prog/nsnotifyd/>


Build and install
-----------------

To install in your home directory,

        $ ./configure
        $ make all
        $ make install

See the top of the Makefile for variables that control the install
location, for example,

        $ sudo make prefix=/usr/local install

[On FreeBSD, use the `nsnotifyd` port or package](https://www.freshports.org/dns/nsnotifyd/)


Dependencies
------------

The main requirement is the BIND-8 libc resolver. BSD and Mac OS ship
with a suitable resolver. On old Debian-like Linux you can `apt
install libbind4-dev` (but it is no longer present in more recent
distributions). Otherwise, the configure script will download libbind
and build and link with it statically.


Latest release
--------------

Download the full source archives:

  * <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.6.tar.xz>
  * <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.6.tar.gz>
  * <http://dotat.at/prog/nsnotifyd/nsnotifyd-1.6.zip>

(Do not use GitHub's "Download ZIP" feature because it gives you
a broken partial copy that contains neither dev support files nor
release build output files.)


Source repositories
-------------------

You can clone or browse the repository from:

  * git://dotat.at/nsnotifyd.git
  * <http://dotat.at/cgi/git/nsnotifyd.git>
  * <https://github.com/fanf2/nsnotifyd.git>


Articles about nsnotifyd
------------------------

  * <http://fanf.livejournal.com/134988.html> nsnotifyd-1.0 announcement
  * <http://fanf.livejournal.com/135257.html> nsnotifyd-1.1 announcement
  * <http://jpmens.net/2015/06/16/alert-on-dns-notify/> review by JP Mens
  * <https://www.theguardian.com/info/developer-blog/2016/dec/23/multiple-dns-synchronising-dyn-to-aws-route-53> how the Guardian synchronized their DNS between Dyn and AWS Route 53 with `nsnotifyd`

And in other media...

  * [TechSNAP 329: teeny weeny DNS server](http://www.jupiterbroadcasting.com/116921/teeny-weeny-dns-server-techsnap-329/) -
    video review by Dan Langille


Contributing
------------

Please send bug reports or patches by email to me. I accept
contributions made under the terms of CC0. Thanks to Gavin Brown,
Niels Haarbo, JP Mens, and Richard James Salts for helpful feedback
and encouragement.

You may do anything with this. It has no warranty.  
<http://creativecommons.org/publicdomain/zero/1.0/>
