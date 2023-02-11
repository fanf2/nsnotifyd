#!/bin/sh

set -e

# build will fail if there is neither .git nor version.h
[ ! -d .git ] && exit

G=$(git describe --dirty=.XXX --always)
V=$(echo $G | sed 's|-g*|.|g;s|[.]|-|')

case $V in
(*.XXX)	# suppress output from make if there is nothing to do
	make -q version/dirty-date >/dev/null ||
	    make version/dirty-date 1>&2
	D="$(version/dirty-date $(git ls-files))"
	;;
(*)	D="$(git show -s --format=%ci HEAD)"
	;;
esac

if [ -f version.h ]
then mv version.h version.h~
fi

( printf '#define VERSION "%s"\n' "$V"
  printf '#define REVDATE "%s"\n' "$D"
) >version.h

TD=$(echo "$D" | sed 's/[^0-9]//g;s/....$//;s/..$/.&/')
touch -t $TD version.h

if [ -f version.h~ ]
then diff -u version.h~ version.h | sed '/#define/!d;s///'
fi
