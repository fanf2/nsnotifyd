#!/bin/sh
set -e

case $# in
(0)	# get $VERSION $REVDATE
	eval $(sed 's/#define //;s/ /=/' version.h)
	V=$VERSION
	;;
(1)	V=$1
	;;
(*)	echo 1>&2 'usage: version/bump.sh [name-number]'
	exit 1
	;;
esac

R=$(echo $V | sed 's/-[0-9].*/-[0-9a-f.]*/')
sed -i~ "s/$R/$V./" README.md

case $# in
(0)	git diff
	;;
(1)	git commit -a -m $V
	git tag -m $V $V
	;;
esac
