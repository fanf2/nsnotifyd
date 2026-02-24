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
  * [dumpaxfr.1](html/dumpaxfr.1.html), the `dumpaxfr` debugging utility

The `nsnotifyd` homepage is <https://dotat.at/prog/nsnotifyd/>


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

The main requirement is the BIND-8 stub resolver. Most BSDs (including
Mac OS) ship with a suitable resolver. Otherwise, the configure script
will download libbind and build and link with it statically.

You can build with libbind instead of the system resolver with

        $ ./configure --with-libbind


Latest release
--------------

Download the full source archives:

  * <https://dotat.at/prog/nsnotifyd/nsnotifyd-2.4.tar.xz>
  * <https://dotat.at/prog/nsnotifyd/nsnotifyd-2.4.tar.gz>
  * <https://dotat.at/prog/nsnotifyd/nsnotifyd-2.4.zip>


Source repositories
-------------------

You can clone or browse the repository from:

  * git://dotat.at/nsnotifyd.git
  * <https://dotat.at/cgi/git/nsnotifyd.git>
  * <https://codeberg.org/fanf/nsnotifyd>


Articles about nsnotifyd
------------------------

  * [https://dotat.at/@/2024-12-05](https://dotat.at/@/2024-12-05-nsnotifyd-2-3-released.html)
    nsnotifyd-2.3 announcement
  * [https://dotat.at/@/2024-11-28](https://dotat.at/@/2024-11-28-nsnotifyd-2-2-released.html)
    nsnotifyd-2.2 announcement
  * [https://dotat.at/@/2024-06-12](https://dotat.at/@/2024-06-12-nsnotifyd-2-1-released.html)
    nsnotifyd-2.1 announcement
  * [https://dotat.at/@/2022-01-25](https://dotat.at/@/2022-01-25-nsnotifyd-2-0-released.html)
    nsnotifyd-2.0 announcement
  * [https://dotat.at/@/2015-07-02](https://dotat.at/@/2015-07-02-nsnotifyd-1-1-prompt-dns-zone-transfers-for-stealth-secondaries.html)
    nsnotifyd-1.1 announcement
  * [https://dotat.at/@/2015-06-15](https://dotat.at/@/2015-06-15-nsnotifyd-handle-dns-notify-messages-by-running-a-command.html)
    nsnotifyd-1.0 announcement
  * <https://jpmens.net/2015/06/16/alert-on-dns-notify/> review by JP Mens
  * [https://www.theguardian.com/info/developer-blog/2016/dec/23/](https://www.theguardian.com/info/developer-blog/2016/dec/23/multiple-dns-synchronising-dyn-to-aws-route-53)
    how the Guardian synchronized their DNS between Dyn and AWS Route 53 with `nsnotifyd`

And in other media...

  * [TechSNAP 329: teeny weeny DNS server](http://www.jupiterbroadcasting.com/116921/teeny-weeny-dns-server-techsnap-329/) -
    video review by Dan Langille


Contributing
------------

Please send bug reports or patches by email to me. I accept
contributions made under the terms of [0BSD][] or [MIT-0][]. Thanks to
Adam Augustine, Athanasius, Gavin Brown, Mark Felder, Niels Haarbo,
Jonathan Hewlett, Dan Langille, Lars-Johann Liman, JP Mens, and
Richard James Salts for helpful feedback and encouragement.

Many thanks to [DK Hostmaster](https://www.dk-hostmaster.dk/)
for sponsoring the 2.0 release.

[0BSD]: https://opensource.org/licenses/0BSD
[MIT-0]: https://opensource.org/licenses/MIT-0


Licence
-------

Written by Tony Finch <<dot@dotat.at>> in Cambridge.

Permission is hereby granted to use, copy, modify, and/or
distribute this software for any purpose with or without fee.

This software is provided 'as is', without warranty of any kind.
In no event shall the authors be liable for any damages arising
from the use of this software.

    SPDX-License-Identifier: 0BSD OR MIT-0

_[this is a zero-conditions libre software licence](https://dotat.at/0lib.html)_
