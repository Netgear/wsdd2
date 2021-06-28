#
# Makefile for wsdd2 WSD/LLMNR server
#
#	Copyright (c) 2016 NETGEAR
#	Copyright (c) 2016 Hiro Sugawara
#

CFLAGS        = -Wall -Wextra -g -O0
LDFLAGS       = -g
OBJFILES      = wsdd2.o wsd.o llmnr.o
HEADERS       = wsdd.h wsd.h

INSTALLPREFIX ?= $(PREFIX)/usr
SBINDIR       ?= sbin
MANDIR        ?= share/man
LIBDIR        ?= lib

SBININSTALLDIR = $(INSTALLPREFIX)/$(SBINDIR)
MANINSTALLDIR = $(INSTALLPREFIX)/$(MANDIR)
LIBINSTALLDIR = $(LIBDIR)

all: wsdd2

nl_debug: CPPFLAGS+=-DMAIN
nl_debug: nl_debug.c; $(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@

wsdd2: $(OBJFILES)
$(OBJFILES): $(HEADERS) Makefile

install: wsdd2
	install -d $(DESTDIR)/$(SBININSTALLDIR)
	install wsdd2 $(DESTDIR)/$(SBININSTALLDIR)
	install -d $(DESTDIR)/$(MANINSTALLDIR)/man8
	install wsdd2.8 $(DESTDIR)/$(MANINSTALLDIR)/man8/wsdd2.8
	install -d $(DESTDIR)/$(LIBINSTALLDIR)/systemd/system
	install -m 0644 wsdd2.service $(DESTDIR)/$(LIBINSTALLDIR)/systemd/system

clean:
	rm -f wsdd2 nl_debug $(OBJFILES)
