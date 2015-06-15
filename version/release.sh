#!/bin/sh
set -e

# get $VERSION $REVDATE
eval $(sed 's/#define //;s/ /=/' version.h)
V=$VERSION

mkdir $V
for f in $(git ls-files | fgrep -v .git) "$@"
do	d=$(dirname $f)
	mkdir -p $V/$d
	cp $f $V/$f
done
zip -qr $V.zip $V
tar cf $V.tar $V
xz -k9 $V.tar
gzip -9 $V.tar
rm -R $V
