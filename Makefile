INCLUDEDIR:=include
LIBS:= -lpcap -lpthread -lpcre

DEFINES:=-D_REENTRANT 
CFLAGS:=-g -O0 -Wall -rdynamic -std=gnu89
LDFLAGS=: -liconv 
CC:=gcc
PROG:=pal
INCLUDES:= -I${INCLUDEDIR} 
DEPDIR:=deps

SOURCES:=$(wildcard *.c)
OBJECTS:=${SOURCES:.c=.o}


.PHONY: clean install check depend

all: check depend ${PROG}

$(PROG): ${OBJECTS}
	${CC} ${CFLAGS}  $^ -o $@ ${LIBS}

${OBJECTS}: ${SOURCES} 
	${CC} ${CFLAGS} ${INCLUDES} ${DEFINES} $^ -c

depend: 
	${CC} ${INCLUDES} -M -MM -MD ${SOURCES}
	[ -d "${DEPDIR}" ] || mkdir ${DEPDIR}
	mv *.d ${DEPDIR}

clean:
	rm -f ${DEPDIR}/*.d
	rm -f *.o ${PROG}

check:
	@if [ "`uname`" != "Linux" ]; then \
		echo "Sorry, linux required, not `uname`"; \
		exit 1; \
	fi

install:

-include ${DEPDIR}/*.d
