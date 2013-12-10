#!/bin/bash

if [ -f Makefile ]; then
	make clean
fi
rm -rf autom4te.cache m4 aclocal.m4 config.* configure depcomp install-sh
rm -rf libtool ltmain.sh Makefile Makefile.in missing test.lo .deps .libs stamp-h1

echo "Cleanup successful"

if [ "$1" = "clean" ]; then
	exit
fi

mkdir m4
autoreconf --install 
autoreconf --install || exit 1
autoreconf -vf || exit 1
