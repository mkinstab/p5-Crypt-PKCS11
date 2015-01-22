#!/bin/sh

if [ -z "$1" -o -z "$2" ]; then
	echo "usage: $0 <file> <object name>"
	exit 1
fi

grep -A 1 sub -- "$1" | \
	perl -ne 's/\{\n//o; print $_;' | \
	grep '^sub' | \
	OBJECT_NAME="$2" perl -ne 's/^sub /=item \$$ENV{OBJECT_NAME}->/o; if(!/\@_/o){s/(=item \S+).*/$1/o;} s/ +my / /o; s/\$self(?:, )?//o; s/\(\)//o; s/ = \@_;//o; print $_,"\n";'
