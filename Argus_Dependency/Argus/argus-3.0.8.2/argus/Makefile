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

# VPATH
srcdir = .


COMPATLIB = -lm -lz
WRAPLIBS = 
SASLLIBS = 

#
# You shouldn't need to edit anything below.
#

CC = gcc
CCOPT = -O
INCLS = -I$(srcdir) -I/usr/include -I$(srcdir)/../include 
DEFS = -DHAVE_CONFIG_H
#DEFS = -DARGUSPERFMETRICS=1 -DHAVE_CONFIG_H


# Standard CFLAGS
CFLAGS = $(CCOPT) $(INCLS) $(DEFS)
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

SRC =	argus.c ArgusModeler.c ArgusSource.c ArgusUtil.c ArgusOutput.c ArgusUdp.c \
	ArgusTcp.c ArgusIcmp.c ArgusIgmp.c ArgusEsp.c ArgusArp.c ArgusFrag.c ArgusUdt.c \
	ArgusLcp.c ArgusIsis.c ArgusAuth.c Argus802.11.c ArgusApp.c ArgusEvents.c \
	ArgusNetflow.c ArgusSflow.c

PROG =	../bin/argus

# We would like to say "OBJ = $(SRC:.c=.o)" but Ultrix's make cannot
# hack the extra indirection

OBJ =	$(SRC:.c=.o)

LIB =  -lpcap -lpthread  $(WRAPLIBS) $(SASLLIBS) $(COMPATLIB) ../lib/argus_common.a -lm

HDR =	pcap.h pcap-int.h pcap-namedb.h pcap-nit.h pcap-pf.h \
	ethertype.h gencode.h gnuc.h

TAGHDR = \
	bpf/net/bpf.h

TAGFILES = \
	$(SRC) $(HDR) $(TAGHDR)

CLEANFILES = $(OBJ) $(PROG)

all: $(PROG)

../bin/argus: $(OBJ) ../lib/argus_common.a
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIB)

install: force all
	[ -d $(DESTDIR)$(SBINDIR) ] || \
		(mkdir -p $(DESTDIR)$(SBINDIR); chmod 755 $(DESTDIR)$(SBINDIR))
	$(INSTALL) $(srcdir)/../bin/argus $(DESTDIR)$(SBINDIR)/argus

uninstall: force
	rm -f $(DESTDIR)$(SBINDIR)/argus

clean:
	rm -f $(CLEANFILES)

distclean:
	rm -f $(CLEANFILES) Makefile config.cache config.log config.status \
	    gnuc.h os-proto.h bpf_filter.c net

tags: $(TAGFILES)
	ctags -wtd $(TAGFILES)

tar:	force
	@cwd=`pwd` ; dir=`basename $$cwd` ; name=libpcap-`cat VERSION` ; \
	    list="" ; tar="tar chFFf" ; \
	    for i in `cat FILES` ; do list="$$list $$name/$$i" ; done; \
	    echo \
	    "rm -f ../$$name; ln -s $$dir ../$$name" ; \
	     rm -f ../$$name; ln -s $$dir ../$$name ; \
	    echo \
	    "(cd .. ; $$tar - [lots of files]) | compress > /tmp/$$name.tar.Z" ; \
	     (cd .. ; $$tar - $$list) | compress > /tmp/$$name.tar.Z ; \
	    echo \
	    "rm -f ../$$name" ; \
	     rm -f ../$$name

force:	/tmp
depend:	force
	../bin/mkdep -c $(CC) $(CFLAGS) $(DEFS) $(INCLS) $(SRC)
