#!/bin/sh
set -eux

for file in "$@"
do
	# get $VERSION $REVDATE
	eval $(sed 's/#define //;s/ /=/' version.h)
	# get $Y $M $D
	eval $(echo $REVDATE | sed 's/ .*//;s/^/Y=/;s/-0*/ M=/;s/-0*/ D=/')
	set - January February March April May June July \
	    August September October November December
	eval M='${'$M'}'
	sed "	s/^\.Dd .*/.Dd $M $D, $Y/;
		s/^Version .* dated .*/Version $VERSION dated $REVDATE/;
	" <"$file" >"$file".new
	if diff -U0 "$file" "$file".new
	then rm "$file".new
	else mv "$file".new "$file"
	fi
done
