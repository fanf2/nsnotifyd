nsnotifyd: handle DNS NOTIFY messages by running a command
----------------------------------------------------------

The `nsnotifyd` daemon monitors a set of DNS zones and runs a command
when any of them change. It listens for DNS NOTIFY messages so it can
respond to changes promptly.

To build, type

	 $ ./configure
	 $ make all

### Dependencies

BSD and Mac OS have a sufficiently recent resolver. On a Debian-like
Linux you should install libbind4-dev. Otherwise, the configure script
will download libbind and build and link with it statically.

### Examples

There are two example scripts:

`nsnotify2git` records the history of changes to a set of zones.

`nsnotify2update` uses nsdiff and nsupdate as part of a bump-in-the-wire
DNSSEC signer.

### Documentation

The `nsnotifyd` homepage is <http://dotat.at/prog/nsnotifyd/>

To read the manual, run

	$ man ./nsnotifyd.1

or go to <http://dotat.at/prog/nsnotifyd/nsnotifyd.txt>

### Source repositories

You can clone or browse the repository from:

* git://dotat.at/nsnotifyd.git
* <http://dotat.at/cgi/git/nsnotifyd.git>
* <https://github.com/fanf2/nsnotifyd.git>
* <https://git.csx.cam.ac.uk/x/ucs/ipreg/nsnotifyd.git>

----------------------------------------------------------------

Thanks to JP Mens and Richard James Salts for helpful feedback and
encouragement.

Written by Tony Finch <dot@dotat.at> <fanf2@cam.ac.uk>
at Cambridge University Information Services.

Please send bug reports or patches to me. I accept
contributions made under the terms of CC0.

You may do anything with this software. It has no warranty.
<http://creativecommons.org/publicdomain/zero/1.0/>
