# 
#  Argus Software
#  Copyright (c) 2000-2015 QoSient, LLC
#  All rights reserved.
# 
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
#  IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
#  THIS SOFTWARE.
# 
# Various configurable paths (remember to edit Makefile.in, not Makefile)
#
NOOP = $(SHELL) -c true
NOECHO = @

# Top level hierarchy

prefix = /usr/local
exec_prefix = ${prefix}
datarootdir = ${prefix}/share

# Pathname of directory to install the system binaries
SBINDIR = ${exec_prefix}/sbin
# Pathname of directory to install the system binaries
BINDIR = ${exec_prefix}/bin
# Pathname of directory to install the include files
INCLDEST = ${prefix}/include
# Pathname of directory to install the library
LIBDEST =  ${exec_prefix}/lib
# Pathname of directory to install the man page
MANDEST = ${datarootdir}/man

# Pathname of preferred perl to use for perl scripts
PERL = /usr/bin/perl

# VPATH
srcdir = .


COMPATLIB = -lm -lz
WRAPLIBS = 

#
# You shouldn't need to edit anything below.
#

CC = gcc
CCOPT = -O
INCLS = -I$(srcdir) -I/usr/include -I$(srcdir)/../include 
DEFS = -DHAVE_CONFIG_H
#DEFS = -DARGUSPERFMETRICS=1 -DHAVE_CONFIG_H


# Standard CFLAGS
CFLAGS = $(CCOPT) @LBL_CFLAGS@ $(INCLS) $(DEFS)
LDFLAGS = 

INSTALL = /usr/bin/install -c
RANLIB = ranlib

#
# Flex and bison allow you to specify the prefixes of the global symbols
# used by the generated parser.  This allows programs to use lex/yacc
# and link against libpcap.  If you don't have flex or bison, get them.
#
LEX = flex -Pargus_
YACC = bison -y -p argus_

# Explicitly define compilation rule since SunOS 4's make doesn't like gcc.
# Also, gcc does not remove the .o before forking 'as', which can be a
# problem if you don't own the file but can write to the directory.
.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $<

SRC =	argus-extip.pl argus-lsof.pl argus-snmp.sh argus-vmstat.sh

PROG =	../bin/argus-extip ../bin/argus-lsof ../bin/argus-snmp ../bin/argus-vmstat

CLEANFILES = $(PROG)

all: $(PROG)

../bin/argus-extip: argus-extip.pl
	sed 's+@PERLBIN@+$(PERL)+' argus-extip.pl > $@
	chmod +x $@

../bin/argus-lsof: argus-lsof.pl
	sed 's+@PERLBIN@+$(PERL)+' argus-lsof.pl > $@
	chmod +x $@

../bin/argus-snmp: argus-snmp.sh
	cp -f argus-snmp.sh $@

../bin/argus-vmstat: argus-vmstat.sh
	cp -f argus-vmstat.sh $@

install: all force
	[ -d $(DESTDIR)$(SBINDIR) ] || \
		(mkdir -p $(DESTDIR)$(SBINDIR); chmod 755 $(DESTDIR)$(SBINDIR))
	$(INSTALL) $(srcdir)/../bin/argus-extip  $(DESTDIR)$(BINDIR)/argus-extip
	$(INSTALL) $(srcdir)/../bin/argus-lsof   $(DESTDIR)$(BINDIR)/argus-lsof
	$(INSTALL) $(srcdir)/../bin/argus-snmp   $(DESTDIR)$(BINDIR)/argus-snmp
	$(INSTALL) $(srcdir)/../bin/argus-vmstat $(DESTDIR)$(BINDIR)/argus-vmstat

uninstall: all force
	rm -f $(DESTDIR)$(BINDIR)/argus-extip
	rm -f $(DESTDIR)$(BINDIR)/argus-lsof
	rm -f $(DESTDIR)$(BINDIR)/argus-snmp
	rm -f $(DESTDIR)$(BINDIR)/argus-vmstat

clean:
	rm -f $(CLEANFILES)

distclean:
	rm -f $(CLEANFILES) Makefile

force:	/tmp
depend:	force
	$(NOECHO) $(NOOP)
