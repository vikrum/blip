# blip Makefile w00p
#
# $Id: Makefile,v 1.3 2001/10/08 20:39:37 vikrum Exp $
#
INCLUDES=common.h dns-build.h dns.h ip.h udp-io.h udp.h mt19937int.h
CFLAGS=-Wall -Wstrict-prototypes -O3 -fno-common -fomit-frame-pointer
CC=gcc
OBJS=common.o dns-build.o udp-io.o mt19937int.o
BLIP= blip

all:	$(BLIP)

$(BLIP):	build_id $(OBJS)
	$(CC) $(OBJS) blip.c ${CFLAGS} -o $(BLIP)

build_id:
	echo "static char build_id[] = \"`date` by `whoami` in `pwd`\n\";" > build_id.h

clean:
	rm -f blip core *.o build_id.h
