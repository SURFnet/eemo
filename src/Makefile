# $Id$

CFLAGS=-g -Wall -Werror
LDFLAGS=-lpcap
EEMO_OBJECTS=\
eemo_packet.o \
ether_handler.o \
ifaddr_lookup.o \
ether_capture.o \
ip_handler.o \
udp_handler.o \
eemo_main.o

all: eemo

eemo: ${EEMO_OBJECTS}
	${CC} ${LDFLAGS} -o eemo ${EEMO_OBJECTS}

clean:
	rm -f eemo *.o

