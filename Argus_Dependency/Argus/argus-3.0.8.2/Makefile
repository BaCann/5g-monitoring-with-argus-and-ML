#
# Makefile for Argus
# Copyright (C) 1996-2015 QoSient, LLC
# All rights reserved

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

#### Start of system configuration section. ####


CC = gcc

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

DEFS = -DHAVE_CONFIG_H
LIBS =  -lpcap
WRAPLIBS = 

prefix = /usr/local
exec_prefix = ${prefix}
datarootdir = ${prefix}/share
srcdir = .
docdir = ${datarootdir}/doc/argus-3.0


#### End of system configuration section. ####

SHELL = /bin/sh

DIRS = ./common ./argus ./events
INSTDIRS = ./argus ./events

DISTFILES = AUTHORS COPYING ChangeLog INSTALL MANIFEST Makefile.in\
	CREDITS README VERSION bin common argus events doc include pkg debian\
	lib man support aclocal.m4 acsite.m4 config configure configure.ac\
	lib/argus.spec .threads

.c.o:
	$(CC) -c $(CPPFLAGS) $(DEFS) $(CFLAGS) $<

.PHONY: install installdirs all

all: force
	@-for d in $(DIRS);\
	do \
		(cd $$d; echo "### Making in" `pwd`;\
			$(MAKE) $(MFLAGS) ;\
			echo "### Done with" `pwd`);\
	done

install:  force
	$(MAKE) $(MFLAGS) installdirs
	[ -d $(DESTDIR)/usr/local ] || \
		(mkdir -p $(DESTDIR)/usr/local; chmod 755 $(DESTDIR)/usr/local)
	[ -d $(DESTDIR)${exec_prefix}/sbin ] || \
		(mkdir -p $(DESTDIR)${exec_prefix}/sbin; chmod 755 $(DESTDIR)${exec_prefix}/sbin)
	[ -d $(DESTDIR)${exec_prefix}/bin ] || \
		(mkdir -p $(DESTDIR)${exec_prefix}/bin; chmod 755 $(DESTDIR)${exec_prefix}/bin)
	[ -d $(DESTDIR)$(exec_prefix)/argus ] || \
		(mkdir -p $(DESTDIR)$(exec_prefix)/argus; chmod 755 $(DESTDIR)$(exec_prefix)/argus)
	[ -d $(DESTDIR)$(exec_prefix)/argus/archive ] || \
		(mkdir -p $(DESTDIR)$(exec_prefix)/argus/archive; chmod 755 $(DESTDIR)$(exec_prefix)/argus/archive)

	@-for d in $(DIRS); \
	do \
		(cd $$d; echo "### Make install in" `pwd`;    \
			$(MAKE) $(MFLAGS) install;    \
			echo "### Done with" `pwd`);            \
	done

	$(INSTALL) -m 0755 $(srcdir)/bin/argusbug $(DESTDIR)${exec_prefix}/bin/argusbug

	[ -d $(DESTDIR)${datarootdir}/man ] || \
		(mkdir -p $(DESTDIR)${datarootdir}/man; chmod 755 $(DESTDIR)${datarootdir}/man)
	[ -d $(DESTDIR)${datarootdir}/man/man5 ] || \
		(mkdir -p $(DESTDIR)${datarootdir}/man/man5; chmod 755 $(DESTDIR)${datarootdir}/man/man5)
	[ -d $(DESTDIR)${datarootdir}/man/man8 ] || \
		(mkdir -p $(DESTDIR)${datarootdir}/man/man8; chmod 755 $(DESTDIR)${datarootdir}/man/man8)
	$(INSTALL) -m 0644 $(srcdir)/man/man5/argus.conf.5 $(DESTDIR)${datarootdir}/man/man5/argus.conf.5
	$(INSTALL) -m 0644 $(srcdir)/man/man8/argus.8 $(DESTDIR)${datarootdir}/man/man8/argus.8

install-doc:  force
	$(MAKE) installdirs
	[ -d $(DESTDIR)/usr/local ] || \
		(mkdir -p $(DESTDIR)/usr/local; chmod 755 $(DESTDIR)/usr/local)
	[ -d $(DESTDIR)$(docdir) ] || \
		(mkdir -p $(DESTDIR)$(docdir); chmod 755 $(DESTDIR)$(docdir))
	$(INSTALL) -m 0644 $(srcdir)/README $(DESTDIR)$(docdir)
	$(INSTALL) -m 0644 $(srcdir)/COPYING $(DESTDIR)$(docdir)

uninstall:
	rm -f $(DESTDIR)${datarootdir}/man/man5/argus.5
	rm -f $(DESTDIR)${datarootdir}/man/man5/argus.conf.5
	rm -f $(DESTDIR)${datarootdir}/man/man8/argus.8
	rm -rf $(DESTDIR)$(docdir)
	@for i in  $(INSTDIRS) ; do \
		if [ -d $$i ] ; then \
		cd $$i; \
		$(MAKE) $(MFLAGS) uninstall; \
		cd ..; \
		fi; \
	done
	rm -f $(DESTDIR)${exec_prefix}/bin/argusbug

installdirs:
	${srcdir}/config/mkinstalldirs $(DESTDIR)$(bindir) $(DESTDIR)$(mandir)\
		$(DESTDIR)$(docdir) $(DESTDIR)$(exec_prefix)/argus/archive

Makefile: Makefile.in config.status
	$(SHELL) config.status

config.status: configure
	$(srcdir)/configure --no-create

TAGS: $(SRCS)
	etags $(SRCS)

.PHONY: clean mostlyclean distclean realclean dist

clean: force
	@-for d in $(DIRS); \
	do \
		(cd $$d; echo "### Make clean in" `pwd`; \
			$(MAKE) $(MFLAGS) clean; \
			echo "### Done with" `pwd`); \
	done

mostlyclean: clean

distclean: force
	@-for d in $(DIRS); \
	do \
		(cd $$d; echo "### Make distclean in" `pwd`; \
			$(MAKE) $(MFLAGS) distclean; \
			echo "### Done with" `pwd`); \
	done
	rm -rf log
	rm -f config.*
	rm -f TAGS
	rm -f lib/*.a
	rm -f bin/*.exe
	rm -f include/argus_config.h

clobber realclean: distclean
	rm -f ./Makefile

dist: distclean
	echo argus-`cat VERSION` > .fname
	rm -rf `cat .fname`
	mkdir `cat .fname`
	tar cf - $(DISTFILES) | (cd `cat .fname`; tar xpf -)
	ls -lR `cat .fname` | fgrep CVS: | sed 's/:$///' > exfile
	tar -X exfile -chozf `cat .fname`.tar.gz `cat .fname`
	rm -rf `cat .fname` .fname exfile

force:  /tmp
depend: force
	@for i in $(DIRS) ; do \
		if [ -d $$i ] ; then \
		cd $$i; \
		$(MAKE) $(MFLAGS) depend || exit 1; \
		cd ..; \
		fi; \
	done

# Prevent GNU make v3 from overflowing arg limit on SysV.
.NOEXPORT:
