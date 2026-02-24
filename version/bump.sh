#!/bin/sh
#
# SPDX-License-Identifier: 0BSD OR MIT-0

set -eux

case $# in
(1)	V=$1
	if git describe $V 2>/dev/null
	then echo 1>&2 'tag already exists'
	     exit 1
	fi
	;;
(*)	echo 1>&2 'usage: version/bump.sh [name-number]'
	exit 1
	;;
esac

./configure

git commit --allow-empty -m $V
git tag -m $V $V

# update documentation to match new version
make doc
R=$(echo $V | sed 's/-[0-9].*/-[0-9a-f.]*/')
sed -i~ "s|/$R[.]|/$V.|" README.md
make html/index.html
git add --update
git commit --amend --no-edit
git tag --force -m $V $V HEAD

# git-archive includes clean version.h
make version.h
git add --force version.h
git commit --amend --no-edit
git tag --force -m $V $V HEAD

make release

git rm version.h
git commit -m 'release done'
