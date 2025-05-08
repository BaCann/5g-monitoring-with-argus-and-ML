/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         argus_parse
#define yylex           argus_lex
#define yyerror         argus_error
#define yydebug         argus_debug
#define yynerrs         argus_nerrs
#define yylval          argus_lval
#define yychar          argus_char

/* First part of user prologue.  */
#line 1 "grammar.y"

/* Argus-5.0 Software.  Common library routines - Grammar files
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software, released under the GNU General
 * Public License; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or any later version.
 *
 * Other licenses are available through QoSient, LLC.
 * Inquire at info@qosient.com.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/argus/common/grammar.y#6 $
 * $DateTime: 2015/06/22 17:59:06 $
 * $Change: 3024 $
 */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994
 *	The Regents of the University of California.  Af rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) af advertising materials mentioning
 * features or use of this software display the fofowing acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifdef HAVE_CONFIG_H
#include <argus_config.h>
#endif

#include <argus_compat.h>
#include <sys/types.h>

#if defined(HAVE_SOLARIS) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/socket.h>
#endif

#include <stdlib.h>
#include <sys/time.h>
#include <net/if.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>

#include <argus_filter.h>

#include <argus_ethertype.h>
#include <argus_compat.h>

#include <syslog.h>

extern void ArgusLog (int, char *, ...);
extern int argus_error (char *);

#define YYDEBUG		1

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

int argus_n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF};


#line 169 "y.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_ARGUS_Y_TAB_H_INCLUDED
# define YY_ARGUS_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int argus_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    START = 258,                   /* START  */
    STOP = 259,                    /* STOP  */
    STATUS = 260,                  /* STATUS  */
    SHUTDOWN = 261,                /* SHUTDOWN  */
    ERROR = 262,                   /* ERROR  */
    MAN = 263,                     /* MAN  */
    FAR = 264,                     /* FAR  */
    EVENT = 265,                   /* EVENT  */
    INDEX = 266,                   /* INDEX  */
    DST = 267,                     /* DST  */
    SRC = 268,                     /* SRC  */
    HOST = 269,                    /* HOST  */
    INODE = 270,                   /* INODE  */
    GATEWAY = 271,                 /* GATEWAY  */
    IPID = 272,                    /* IPID  */
    TTL = 273,                     /* TTL  */
    TOS = 274,                     /* TOS  */
    DSB = 275,                     /* DSB  */
    SRCID = 276,                   /* SRCID  */
    TCPBASE = 277,                 /* TCPBASE  */
    NET = 278,                     /* NET  */
    AMASK = 279,                   /* AMASK  */
    PORT = 280,                    /* PORT  */
    EQUAL = 281,                   /* EQUAL  */
    LESS = 282,                    /* LESS  */
    GREATER = 283,                 /* GREATER  */
    PROTO = 284,                   /* PROTO  */
    BYTE = 285,                    /* BYTE  */
    PKT = 286,                     /* PKT  */
    APPBYTE = 287,                 /* APPBYTE  */
    TRANS = 288,                   /* TRANS  */
    ARP = 289,                     /* ARP  */
    RARP = 290,                    /* RARP  */
    IP = 291,                      /* IP  */
    IPV4 = 292,                    /* IPV4  */
    IPV6 = 293,                    /* IPV6  */
    TCP = 294,                     /* TCP  */
    UDP = 295,                     /* UDP  */
    ICMP = 296,                    /* ICMP  */
    IGMP = 297,                    /* IGMP  */
    ISIS = 298,                    /* ISIS  */
    HELLO = 299,                   /* HELLO  */
    LSP = 300,                     /* LSP  */
    CSNP = 301,                    /* CSNP  */
    PSNP = 302,                    /* PSNP  */
    UDT = 303,                     /* UDT  */
    SVC = 304,                     /* SVC  */
    TCPRTT = 305,                  /* TCPRTT  */
    TCPOPT = 306,                  /* TCPOPT  */
    MSS = 307,                     /* MSS  */
    WSCALE = 308,                  /* WSCALE  */
    SELECTIVEACKOK = 309,          /* SELECTIVEACKOK  */
    SELECTIVEACK = 310,            /* SELECTIVEACK  */
    TCPECHO = 311,                 /* TCPECHO  */
    TCPECHOREPLY = 312,            /* TCPECHOREPLY  */
    TCPTIMESTAMP = 313,            /* TCPTIMESTAMP  */
    TCPCC = 314,                   /* TCPCC  */
    TCPCCNEW = 315,                /* TCPCCNEW  */
    TCPCCECHO = 316,               /* TCPCCECHO  */
    SECN = 317,                    /* SECN  */
    DECN = 318,                    /* DECN  */
    ETHER = 319,                   /* ETHER  */
    MPLS = 320,                    /* MPLS  */
    VLAN = 321,                    /* VLAN  */
    ANON = 322,                    /* ANON  */
    VID = 323,                     /* VID  */
    VPRI = 324,                    /* VPRI  */
    MPLSID = 325,                  /* MPLSID  */
    SPI = 326,                     /* SPI  */
    ENCAPS = 327,                  /* ENCAPS  */
    RTP = 328,                     /* RTP  */
    RTCP = 329,                    /* RTCP  */
    ESP = 330,                     /* ESP  */
    DECNET = 331,                  /* DECNET  */
    LAT = 332,                     /* LAT  */
    MOPRC = 333,                   /* MOPRC  */
    MOPDL = 334,                   /* MOPDL  */
    TK_BROADCAST = 335,            /* TK_BROADCAST  */
    TK_MULTICAST = 336,            /* TK_MULTICAST  */
    FRAG = 337,                    /* FRAG  */
    FRAG_ONLY = 338,               /* FRAG_ONLY  */
    ABR = 339,                     /* ABR  */
    PCR = 340,                     /* PCR  */
    RATE = 341,                    /* RATE  */
    LOAD = 342,                    /* LOAD  */
    LOSS = 343,                    /* LOSS  */
    PLOSS = 344,                   /* PLOSS  */
    GAP = 345,                     /* GAP  */
    DUP = 346,                     /* DUP  */
    CO = 347,                      /* CO  */
    INTER = 348,                   /* INTER  */
    INTERACTIVE = 349,             /* INTERACTIVE  */
    INTERIDLE = 350,               /* INTERIDLE  */
    JITTER = 351,                  /* JITTER  */
    JITTERACTIVE = 352,            /* JITTERACTIVE  */
    JITTERIDLE = 353,              /* JITTERIDLE  */
    DUR = 354,                     /* DUR  */
    AVGDUR = 355,                  /* AVGDUR  */
    DELTADUR = 356,                /* DELTADUR  */
    DELTASTART = 357,              /* DELTASTART  */
    DELTALAST = 358,               /* DELTALAST  */
    DELTASPKTS = 359,              /* DELTASPKTS  */
    DELTADPKTS = 360,              /* DELTADPKTS  */
    SEQ = 361,                     /* SEQ  */
    NSTROKE = 362,                 /* NSTROKE  */
    INBOUND = 363,                 /* INBOUND  */
    OUTBOUND = 364,                /* OUTBOUND  */
    LINK = 365,                    /* LINK  */
    AUTH = 366,                    /* AUTH  */
    RECURS = 367,                  /* RECURS  */
    REQ = 368,                     /* REQ  */
    RSP = 369,                     /* RSP  */
    GEQ = 370,                     /* GEQ  */
    LEQ = 371,                     /* LEQ  */
    NEQ = 372,                     /* NEQ  */
    LSH = 373,                     /* LSH  */
    RSH = 374,                     /* RSH  */
    LEN = 375,                     /* LEN  */
    OUTOFORDER = 376,              /* OUTOFORDER  */
    RETRANS = 377,                 /* RETRANS  */
    NORMAL = 378,                  /* NORMAL  */
    WAIT = 379,                    /* WAIT  */
    MULTIPATH = 380,               /* MULTIPATH  */
    RESET = 381,                   /* RESET  */
    TIMEDOUT = 382,                /* TIMEDOUT  */
    WINSHUT = 383,                 /* WINSHUT  */
    SYN = 384,                     /* SYN  */
    SYNACK = 385,                  /* SYNACK  */
    ACK = 386,                     /* ACK  */
    PUSH = 387,                    /* PUSH  */
    URGENT = 388,                  /* URGENT  */
    DATA = 389,                    /* DATA  */
    ECE = 390,                     /* ECE  */
    CWR = 391,                     /* CWR  */
    FIN = 392,                     /* FIN  */
    FINACK = 393,                  /* FINACK  */
    ICMPECHO = 394,                /* ICMPECHO  */
    ICMPMAP = 395,                 /* ICMPMAP  */
    UNREACH = 396,                 /* UNREACH  */
    REDIRECT = 397,                /* REDIRECT  */
    ECN = 398,                     /* ECN  */
    TIMEXED = 399,                 /* TIMEXED  */
    ESTABLISHED = 400,             /* ESTABLISHED  */
    CONNECTED = 401,               /* CONNECTED  */
    CORRELATED = 402,              /* CORRELATED  */
    RTR = 403,                     /* RTR  */
    MBR = 404,                     /* MBR  */
    LVG = 405,                     /* LVG  */
    COCODE = 406,                  /* COCODE  */
    ASN = 407,                     /* ASN  */
    ID = 408,                      /* ID  */
    EID = 409,                     /* EID  */
    HIDV4 = 410,                   /* HIDV4  */
    HIDV6 = 411,                   /* HIDV6  */
    STRING = 412,                  /* STRING  */
    NUM = 413,                     /* NUM  */
    FLOAT = 414,                   /* FLOAT  */
    OR = 415,                      /* OR  */
    AND = 416,                     /* AND  */
    UMINUS = 417                   /* UMINUS  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define START 258
#define STOP 259
#define STATUS 260
#define SHUTDOWN 261
#define ERROR 262
#define MAN 263
#define FAR 264
#define EVENT 265
#define INDEX 266
#define DST 267
#define SRC 268
#define HOST 269
#define INODE 270
#define GATEWAY 271
#define IPID 272
#define TTL 273
#define TOS 274
#define DSB 275
#define SRCID 276
#define TCPBASE 277
#define NET 278
#define AMASK 279
#define PORT 280
#define EQUAL 281
#define LESS 282
#define GREATER 283
#define PROTO 284
#define BYTE 285
#define PKT 286
#define APPBYTE 287
#define TRANS 288
#define ARP 289
#define RARP 290
#define IP 291
#define IPV4 292
#define IPV6 293
#define TCP 294
#define UDP 295
#define ICMP 296
#define IGMP 297
#define ISIS 298
#define HELLO 299
#define LSP 300
#define CSNP 301
#define PSNP 302
#define UDT 303
#define SVC 304
#define TCPRTT 305
#define TCPOPT 306
#define MSS 307
#define WSCALE 308
#define SELECTIVEACKOK 309
#define SELECTIVEACK 310
#define TCPECHO 311
#define TCPECHOREPLY 312
#define TCPTIMESTAMP 313
#define TCPCC 314
#define TCPCCNEW 315
#define TCPCCECHO 316
#define SECN 317
#define DECN 318
#define ETHER 319
#define MPLS 320
#define VLAN 321
#define ANON 322
#define VID 323
#define VPRI 324
#define MPLSID 325
#define SPI 326
#define ENCAPS 327
#define RTP 328
#define RTCP 329
#define ESP 330
#define DECNET 331
#define LAT 332
#define MOPRC 333
#define MOPDL 334
#define TK_BROADCAST 335
#define TK_MULTICAST 336
#define FRAG 337
#define FRAG_ONLY 338
#define ABR 339
#define PCR 340
#define RATE 341
#define LOAD 342
#define LOSS 343
#define PLOSS 344
#define GAP 345
#define DUP 346
#define CO 347
#define INTER 348
#define INTERACTIVE 349
#define INTERIDLE 350
#define JITTER 351
#define JITTERACTIVE 352
#define JITTERIDLE 353
#define DUR 354
#define AVGDUR 355
#define DELTADUR 356
#define DELTASTART 357
#define DELTALAST 358
#define DELTASPKTS 359
#define DELTADPKTS 360
#define SEQ 361
#define NSTROKE 362
#define INBOUND 363
#define OUTBOUND 364
#define LINK 365
#define AUTH 366
#define RECURS 367
#define REQ 368
#define RSP 369
#define GEQ 370
#define LEQ 371
#define NEQ 372
#define LSH 373
#define RSH 374
#define LEN 375
#define OUTOFORDER 376
#define RETRANS 377
#define NORMAL 378
#define WAIT 379
#define MULTIPATH 380
#define RESET 381
#define TIMEDOUT 382
#define WINSHUT 383
#define SYN 384
#define SYNACK 385
#define ACK 386
#define PUSH 387
#define URGENT 388
#define DATA 389
#define ECE 390
#define CWR 391
#define FIN 392
#define FINACK 393
#define ICMPECHO 394
#define ICMPMAP 395
#define UNREACH 396
#define REDIRECT 397
#define ECN 398
#define TIMEXED 399
#define ESTABLISHED 400
#define CONNECTED 401
#define CORRELATED 402
#define RTR 403
#define MBR 404
#define LVG 405
#define COCODE 406
#define ASN 407
#define ID 408
#define EID 409
#define HIDV4 410
#define HIDV6 411
#define STRING 412
#define NUM 413
#define FLOAT 414
#define OR 415
#define AND 416
#define UMINUS 417

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 92 "grammar.y"

	int i;
	float f;
	u_long h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		struct ablock *b;
	} blk;
	struct ablock *rblk;

#line 561 "y.tab.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE argus_lval;


int argus_parse (void);


#endif /* !YY_ARGUS_Y_TAB_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_START = 3,                      /* START  */
  YYSYMBOL_STOP = 4,                       /* STOP  */
  YYSYMBOL_STATUS = 5,                     /* STATUS  */
  YYSYMBOL_SHUTDOWN = 6,                   /* SHUTDOWN  */
  YYSYMBOL_ERROR = 7,                      /* ERROR  */
  YYSYMBOL_MAN = 8,                        /* MAN  */
  YYSYMBOL_FAR = 9,                        /* FAR  */
  YYSYMBOL_EVENT = 10,                     /* EVENT  */
  YYSYMBOL_INDEX = 11,                     /* INDEX  */
  YYSYMBOL_DST = 12,                       /* DST  */
  YYSYMBOL_SRC = 13,                       /* SRC  */
  YYSYMBOL_HOST = 14,                      /* HOST  */
  YYSYMBOL_INODE = 15,                     /* INODE  */
  YYSYMBOL_GATEWAY = 16,                   /* GATEWAY  */
  YYSYMBOL_IPID = 17,                      /* IPID  */
  YYSYMBOL_TTL = 18,                       /* TTL  */
  YYSYMBOL_TOS = 19,                       /* TOS  */
  YYSYMBOL_DSB = 20,                       /* DSB  */
  YYSYMBOL_SRCID = 21,                     /* SRCID  */
  YYSYMBOL_TCPBASE = 22,                   /* TCPBASE  */
  YYSYMBOL_NET = 23,                       /* NET  */
  YYSYMBOL_AMASK = 24,                     /* AMASK  */
  YYSYMBOL_PORT = 25,                      /* PORT  */
  YYSYMBOL_EQUAL = 26,                     /* EQUAL  */
  YYSYMBOL_LESS = 27,                      /* LESS  */
  YYSYMBOL_GREATER = 28,                   /* GREATER  */
  YYSYMBOL_PROTO = 29,                     /* PROTO  */
  YYSYMBOL_BYTE = 30,                      /* BYTE  */
  YYSYMBOL_PKT = 31,                       /* PKT  */
  YYSYMBOL_APPBYTE = 32,                   /* APPBYTE  */
  YYSYMBOL_TRANS = 33,                     /* TRANS  */
  YYSYMBOL_ARP = 34,                       /* ARP  */
  YYSYMBOL_RARP = 35,                      /* RARP  */
  YYSYMBOL_IP = 36,                        /* IP  */
  YYSYMBOL_IPV4 = 37,                      /* IPV4  */
  YYSYMBOL_IPV6 = 38,                      /* IPV6  */
  YYSYMBOL_TCP = 39,                       /* TCP  */
  YYSYMBOL_UDP = 40,                       /* UDP  */
  YYSYMBOL_ICMP = 41,                      /* ICMP  */
  YYSYMBOL_IGMP = 42,                      /* IGMP  */
  YYSYMBOL_ISIS = 43,                      /* ISIS  */
  YYSYMBOL_HELLO = 44,                     /* HELLO  */
  YYSYMBOL_LSP = 45,                       /* LSP  */
  YYSYMBOL_CSNP = 46,                      /* CSNP  */
  YYSYMBOL_PSNP = 47,                      /* PSNP  */
  YYSYMBOL_UDT = 48,                       /* UDT  */
  YYSYMBOL_SVC = 49,                       /* SVC  */
  YYSYMBOL_TCPRTT = 50,                    /* TCPRTT  */
  YYSYMBOL_TCPOPT = 51,                    /* TCPOPT  */
  YYSYMBOL_MSS = 52,                       /* MSS  */
  YYSYMBOL_WSCALE = 53,                    /* WSCALE  */
  YYSYMBOL_SELECTIVEACKOK = 54,            /* SELECTIVEACKOK  */
  YYSYMBOL_SELECTIVEACK = 55,              /* SELECTIVEACK  */
  YYSYMBOL_TCPECHO = 56,                   /* TCPECHO  */
  YYSYMBOL_TCPECHOREPLY = 57,              /* TCPECHOREPLY  */
  YYSYMBOL_TCPTIMESTAMP = 58,              /* TCPTIMESTAMP  */
  YYSYMBOL_TCPCC = 59,                     /* TCPCC  */
  YYSYMBOL_TCPCCNEW = 60,                  /* TCPCCNEW  */
  YYSYMBOL_TCPCCECHO = 61,                 /* TCPCCECHO  */
  YYSYMBOL_SECN = 62,                      /* SECN  */
  YYSYMBOL_DECN = 63,                      /* DECN  */
  YYSYMBOL_ETHER = 64,                     /* ETHER  */
  YYSYMBOL_MPLS = 65,                      /* MPLS  */
  YYSYMBOL_VLAN = 66,                      /* VLAN  */
  YYSYMBOL_ANON = 67,                      /* ANON  */
  YYSYMBOL_VID = 68,                       /* VID  */
  YYSYMBOL_VPRI = 69,                      /* VPRI  */
  YYSYMBOL_MPLSID = 70,                    /* MPLSID  */
  YYSYMBOL_SPI = 71,                       /* SPI  */
  YYSYMBOL_ENCAPS = 72,                    /* ENCAPS  */
  YYSYMBOL_RTP = 73,                       /* RTP  */
  YYSYMBOL_RTCP = 74,                      /* RTCP  */
  YYSYMBOL_ESP = 75,                       /* ESP  */
  YYSYMBOL_DECNET = 76,                    /* DECNET  */
  YYSYMBOL_LAT = 77,                       /* LAT  */
  YYSYMBOL_MOPRC = 78,                     /* MOPRC  */
  YYSYMBOL_MOPDL = 79,                     /* MOPDL  */
  YYSYMBOL_TK_BROADCAST = 80,              /* TK_BROADCAST  */
  YYSYMBOL_TK_MULTICAST = 81,              /* TK_MULTICAST  */
  YYSYMBOL_FRAG = 82,                      /* FRAG  */
  YYSYMBOL_FRAG_ONLY = 83,                 /* FRAG_ONLY  */
  YYSYMBOL_ABR = 84,                       /* ABR  */
  YYSYMBOL_PCR = 85,                       /* PCR  */
  YYSYMBOL_RATE = 86,                      /* RATE  */
  YYSYMBOL_LOAD = 87,                      /* LOAD  */
  YYSYMBOL_LOSS = 88,                      /* LOSS  */
  YYSYMBOL_PLOSS = 89,                     /* PLOSS  */
  YYSYMBOL_GAP = 90,                       /* GAP  */
  YYSYMBOL_DUP = 91,                       /* DUP  */
  YYSYMBOL_CO = 92,                        /* CO  */
  YYSYMBOL_INTER = 93,                     /* INTER  */
  YYSYMBOL_INTERACTIVE = 94,               /* INTERACTIVE  */
  YYSYMBOL_INTERIDLE = 95,                 /* INTERIDLE  */
  YYSYMBOL_JITTER = 96,                    /* JITTER  */
  YYSYMBOL_JITTERACTIVE = 97,              /* JITTERACTIVE  */
  YYSYMBOL_JITTERIDLE = 98,                /* JITTERIDLE  */
  YYSYMBOL_DUR = 99,                       /* DUR  */
  YYSYMBOL_AVGDUR = 100,                   /* AVGDUR  */
  YYSYMBOL_DELTADUR = 101,                 /* DELTADUR  */
  YYSYMBOL_DELTASTART = 102,               /* DELTASTART  */
  YYSYMBOL_DELTALAST = 103,                /* DELTALAST  */
  YYSYMBOL_DELTASPKTS = 104,               /* DELTASPKTS  */
  YYSYMBOL_DELTADPKTS = 105,               /* DELTADPKTS  */
  YYSYMBOL_SEQ = 106,                      /* SEQ  */
  YYSYMBOL_NSTROKE = 107,                  /* NSTROKE  */
  YYSYMBOL_INBOUND = 108,                  /* INBOUND  */
  YYSYMBOL_OUTBOUND = 109,                 /* OUTBOUND  */
  YYSYMBOL_LINK = 110,                     /* LINK  */
  YYSYMBOL_AUTH = 111,                     /* AUTH  */
  YYSYMBOL_RECURS = 112,                   /* RECURS  */
  YYSYMBOL_REQ = 113,                      /* REQ  */
  YYSYMBOL_RSP = 114,                      /* RSP  */
  YYSYMBOL_GEQ = 115,                      /* GEQ  */
  YYSYMBOL_LEQ = 116,                      /* LEQ  */
  YYSYMBOL_NEQ = 117,                      /* NEQ  */
  YYSYMBOL_LSH = 118,                      /* LSH  */
  YYSYMBOL_RSH = 119,                      /* RSH  */
  YYSYMBOL_LEN = 120,                      /* LEN  */
  YYSYMBOL_OUTOFORDER = 121,               /* OUTOFORDER  */
  YYSYMBOL_RETRANS = 122,                  /* RETRANS  */
  YYSYMBOL_NORMAL = 123,                   /* NORMAL  */
  YYSYMBOL_WAIT = 124,                     /* WAIT  */
  YYSYMBOL_MULTIPATH = 125,                /* MULTIPATH  */
  YYSYMBOL_RESET = 126,                    /* RESET  */
  YYSYMBOL_TIMEDOUT = 127,                 /* TIMEDOUT  */
  YYSYMBOL_WINSHUT = 128,                  /* WINSHUT  */
  YYSYMBOL_SYN = 129,                      /* SYN  */
  YYSYMBOL_SYNACK = 130,                   /* SYNACK  */
  YYSYMBOL_ACK = 131,                      /* ACK  */
  YYSYMBOL_PUSH = 132,                     /* PUSH  */
  YYSYMBOL_URGENT = 133,                   /* URGENT  */
  YYSYMBOL_DATA = 134,                     /* DATA  */
  YYSYMBOL_ECE = 135,                      /* ECE  */
  YYSYMBOL_CWR = 136,                      /* CWR  */
  YYSYMBOL_FIN = 137,                      /* FIN  */
  YYSYMBOL_FINACK = 138,                   /* FINACK  */
  YYSYMBOL_ICMPECHO = 139,                 /* ICMPECHO  */
  YYSYMBOL_ICMPMAP = 140,                  /* ICMPMAP  */
  YYSYMBOL_UNREACH = 141,                  /* UNREACH  */
  YYSYMBOL_REDIRECT = 142,                 /* REDIRECT  */
  YYSYMBOL_ECN = 143,                      /* ECN  */
  YYSYMBOL_TIMEXED = 144,                  /* TIMEXED  */
  YYSYMBOL_ESTABLISHED = 145,              /* ESTABLISHED  */
  YYSYMBOL_CONNECTED = 146,                /* CONNECTED  */
  YYSYMBOL_CORRELATED = 147,               /* CORRELATED  */
  YYSYMBOL_RTR = 148,                      /* RTR  */
  YYSYMBOL_MBR = 149,                      /* MBR  */
  YYSYMBOL_LVG = 150,                      /* LVG  */
  YYSYMBOL_COCODE = 151,                   /* COCODE  */
  YYSYMBOL_ASN = 152,                      /* ASN  */
  YYSYMBOL_ID = 153,                       /* ID  */
  YYSYMBOL_EID = 154,                      /* EID  */
  YYSYMBOL_HIDV4 = 155,                    /* HIDV4  */
  YYSYMBOL_HIDV6 = 156,                    /* HIDV6  */
  YYSYMBOL_STRING = 157,                   /* STRING  */
  YYSYMBOL_NUM = 158,                      /* NUM  */
  YYSYMBOL_FLOAT = 159,                    /* FLOAT  */
  YYSYMBOL_OR = 160,                       /* OR  */
  YYSYMBOL_AND = 161,                      /* AND  */
  YYSYMBOL_162_ = 162,                     /* '!'  */
  YYSYMBOL_163_ = 163,                     /* '|'  */
  YYSYMBOL_164_ = 164,                     /* '&'  */
  YYSYMBOL_165_ = 165,                     /* '+'  */
  YYSYMBOL_166_ = 166,                     /* '-'  */
  YYSYMBOL_167_ = 167,                     /* '*'  */
  YYSYMBOL_168_ = 168,                     /* '/'  */
  YYSYMBOL_UMINUS = 169,                   /* UMINUS  */
  YYSYMBOL_170_ = 170,                     /* ')'  */
  YYSYMBOL_171_ = 171,                     /* '('  */
  YYSYMBOL_172_ = 172,                     /* '>'  */
  YYSYMBOL_173_ = 173,                     /* '='  */
  YYSYMBOL_174_ = 174,                     /* '<'  */
  YYSYMBOL_175_ = 175,                     /* '['  */
  YYSYMBOL_176_ = 176,                     /* ']'  */
  YYSYMBOL_177_ = 177,                     /* ':'  */
  YYSYMBOL_YYACCEPT = 178,                 /* $accept  */
  YYSYMBOL_prog = 179,                     /* prog  */
  YYSYMBOL_nuf = 180,                      /* nuf  */
  YYSYMBOL_expr = 181,                     /* expr  */
  YYSYMBOL_and = 182,                      /* and  */
  YYSYMBOL_or = 183,                       /* or  */
  YYSYMBOL_id = 184,                       /* id  */
  YYSYMBOL_tid = 185,                      /* tid  */
  YYSYMBOL_oid = 186,                      /* oid  */
  YYSYMBOL_nid = 187,                      /* nid  */
  YYSYMBOL_not = 188,                      /* not  */
  YYSYMBOL_paren = 189,                    /* paren  */
  YYSYMBOL_pid = 190,                      /* pid  */
  YYSYMBOL_qid = 191,                      /* qid  */
  YYSYMBOL_term = 192,                     /* term  */
  YYSYMBOL_head = 193,                     /* head  */
  YYSYMBOL_thead = 194,                    /* thead  */
  YYSYMBOL_rterm = 195,                    /* rterm  */
  YYSYMBOL_pqual = 196,                    /* pqual  */
  YYSYMBOL_dqual = 197,                    /* dqual  */
  YYSYMBOL_aqual = 198,                    /* aqual  */
  YYSYMBOL_iqual = 199,                    /* iqual  */
  YYSYMBOL_fqual = 200,                    /* fqual  */
  YYSYMBOL_ndaqual = 201,                  /* ndaqual  */
  YYSYMBOL_sname = 202,                    /* sname  */
  YYSYMBOL_pname = 203,                    /* pname  */
  YYSYMBOL_tname = 204,                    /* tname  */
  YYSYMBOL_oname = 205,                    /* oname  */
  YYSYMBOL_other = 206,                    /* other  */
  YYSYMBOL_relop = 207,                    /* relop  */
  YYSYMBOL_irelop = 208,                   /* irelop  */
  YYSYMBOL_arth = 209,                     /* arth  */
  YYSYMBOL_narth = 210,                    /* narth  */
  YYSYMBOL_pnum = 211,                     /* pnum  */
  YYSYMBOL_fnum = 212                      /* fnum  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   1426

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  178
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  35
/* YYNRULES -- Number of rules.  */
#define YYNRULES  229
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  280

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   417


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   162,     2,     2,     2,     2,   164,     2,
     171,   170,   167,   165,     2,   166,     2,   168,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   177,     2,
     174,   173,   172,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   175,     2,   176,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   163,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   169
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   163,   163,   167,   169,   171,   172,   173,   174,   175,
     177,   179,   181,   182,   183,   185,   186,   187,   188,   189,
     191,   192,   193,   194,   195,   197,   199,   201,   203,   204,
     206,   208,   210,   212,   214,   216,   218,   220,   222,   224,
     225,   226,   228,   229,   230,   232,   233,   235,   236,   237,
     238,   239,   240,   241,   242,   243,   246,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   262,   263,   266,
     267,   268,   269,   270,   271,   274,   275,   276,   277,   280,
     281,   282,   283,   284,   285,   286,   287,   288,   289,   290,
     291,   292,   293,   294,   295,   296,   297,   298,   299,   300,
     301,   302,   303,   304,   305,   308,   309,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,   320,   323,   326,
     327,   328,   329,   330,   331,   332,   333,   334,   335,   336,
     337,   338,   339,   340,   341,   342,   343,   344,   345,   346,
     347,   348,   349,   350,   351,   352,   355,   356,   357,   358,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,   380,
     381,   382,   383,   384,   385,   386,   387,   388,   389,   390,
     391,   392,   393,   394,   395,   396,   397,   398,   400,   401,
     402,   403,   404,   405,   406,   407,   408,   409,   410,   411,
     412,   415,   416,   417,   418,   420,   421,   422,   423,   425,
     426,   427,   429,   430,   432,   433,   434,   435,   436,   437,
     438,   439,   440,   441,   442,   443,   445,   446,   448,   449
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "START", "STOP",
  "STATUS", "SHUTDOWN", "ERROR", "MAN", "FAR", "EVENT", "INDEX", "DST",
  "SRC", "HOST", "INODE", "GATEWAY", "IPID", "TTL", "TOS", "DSB", "SRCID",
  "TCPBASE", "NET", "AMASK", "PORT", "EQUAL", "LESS", "GREATER", "PROTO",
  "BYTE", "PKT", "APPBYTE", "TRANS", "ARP", "RARP", "IP", "IPV4", "IPV6",
  "TCP", "UDP", "ICMP", "IGMP", "ISIS", "HELLO", "LSP", "CSNP", "PSNP",
  "UDT", "SVC", "TCPRTT", "TCPOPT", "MSS", "WSCALE", "SELECTIVEACKOK",
  "SELECTIVEACK", "TCPECHO", "TCPECHOREPLY", "TCPTIMESTAMP", "TCPCC",
  "TCPCCNEW", "TCPCCECHO", "SECN", "DECN", "ETHER", "MPLS", "VLAN", "ANON",
  "VID", "VPRI", "MPLSID", "SPI", "ENCAPS", "RTP", "RTCP", "ESP", "DECNET",
  "LAT", "MOPRC", "MOPDL", "TK_BROADCAST", "TK_MULTICAST", "FRAG",
  "FRAG_ONLY", "ABR", "PCR", "RATE", "LOAD", "LOSS", "PLOSS", "GAP", "DUP",
  "CO", "INTER", "INTERACTIVE", "INTERIDLE", "JITTER", "JITTERACTIVE",
  "JITTERIDLE", "DUR", "AVGDUR", "DELTADUR", "DELTASTART", "DELTALAST",
  "DELTASPKTS", "DELTADPKTS", "SEQ", "NSTROKE", "INBOUND", "OUTBOUND",
  "LINK", "AUTH", "RECURS", "REQ", "RSP", "GEQ", "LEQ", "NEQ", "LSH",
  "RSH", "LEN", "OUTOFORDER", "RETRANS", "NORMAL", "WAIT", "MULTIPATH",
  "RESET", "TIMEDOUT", "WINSHUT", "SYN", "SYNACK", "ACK", "PUSH", "URGENT",
  "DATA", "ECE", "CWR", "FIN", "FINACK", "ICMPECHO", "ICMPMAP", "UNREACH",
  "REDIRECT", "ECN", "TIMEXED", "ESTABLISHED", "CONNECTED", "CORRELATED",
  "RTR", "MBR", "LVG", "COCODE", "ASN", "ID", "EID", "HIDV4", "HIDV6",
  "STRING", "NUM", "FLOAT", "OR", "AND", "'!'", "'|'", "'&'", "'+'", "'-'",
  "'*'", "'/'", "UMINUS", "')'", "'('", "'>'", "'='", "'<'", "'['", "']'",
  "':'", "$accept", "prog", "nuf", "expr", "and", "or", "id", "tid", "oid",
  "nid", "not", "paren", "pid", "qid", "term", "head", "thead", "rterm",
  "pqual", "dqual", "aqual", "iqual", "fqual", "ndaqual", "sname", "pname",
  "tname", "oname", "other", "relop", "irelop", "arth", "narth", "pnum",
  "fnum", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-155)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-61)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -155,     7,   234,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -146,  -155,  -155,   910,   910,  -155,   954,  1241,
    -155,  1175,  -155,     1,  -155,  -155,  -155,    21,  -155,  -155,
    -155,  -155,   403,   403,  -155,   -71,  -154,  -126,  -134,  -134,
    -134,  -134,  -134,  -155,  -155,   -22,  -107,  -155,  -155,  -155,
    -155,   954,    43,  -155,  -155,  -155,  -142,  -112,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,
    -155,  -155,  -155,  -155,  -155,  1065,  -155,  -155,  -155,  -155,
    1255,  -155,  -155,  -155,  -155,  1255,  1255,  1255,  1255,  1255,
    1255,  1255,  1255,  -155,  -155,  -155,  1255,  1255,  -155,   403,
     572,  -155,     3,  -155,  -155,  -155,  -155,  -155,  -134,  -155,
    -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,  -155,   -93,
     -95,   -76,  -155,  -155,  -105,  -146,  -126,  -104,    66,    82,
      88,    90,  -155,  -155,  -155,  1255,   -72,   -96,  -125,  -125,
     -80,  -110,  -108,  -108,  -155,  -155,   -90,   -90,   741,   -69,
    -126,  -104,  -155,  -155,  -155,  -155,   954,   954,  -155,  -155,
    -155,  -155,  -155,   -90,  -155,   -52,  -155,  -155,   -67,  -155
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       4,     0,    68,     1,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   151,   152,   148,   149,   150,   156,   157,
     158,   159,   161,   184,   185,   186,   187,   163,   128,   188,
     189,   190,   191,   192,   193,   194,   195,   196,   197,   198,
     199,   200,   147,   160,   162,   164,   154,   155,   153,   165,
     166,   168,   167,   180,   181,   203,   204,   146,   225,   169,
     170,   129,   130,   183,   174,   136,   171,   172,   131,   175,
     176,   177,   179,   178,   173,   132,   138,   137,   139,   140,
     182,   141,   133,   134,   135,   142,   143,   144,   145,   226,
      37,    38,     2,    62,    63,    68,    68,     5,     0,     0,
      45,     0,    61,    67,    26,    27,    66,     0,   213,   212,
      11,    10,    68,    68,    46,     0,   213,   212,     0,     0,
       0,     0,     0,    28,    35,    32,    34,    29,   228,    57,
      12,     0,     0,    13,    14,    58,    70,    69,    75,    77,
     118,    80,    81,    82,    83,    76,    94,    78,    79,    54,
      89,    91,    90,    92,    93,    86,    87,    88,    98,    99,
     201,   202,   116,   117,   113,   114,    95,   115,    96,    97,
      84,   107,   108,   109,   110,   111,   112,   105,   106,   100,
     101,   102,   104,   103,    85,    56,    49,    50,    51,    55,
       0,   208,   206,   209,   211,     0,     0,     0,     0,     0,
       0,     0,     0,   205,   207,   210,     0,     0,     7,    68,
      68,     6,   212,     9,     8,    59,   224,   227,     0,    17,
      22,    15,    20,    16,    21,    18,    23,    19,    24,     0,
       0,     0,    36,    39,    44,     0,    42,    43,     0,     0,
       0,     0,    47,    52,    53,     0,     0,     0,   222,   223,
     221,   220,   216,   217,   218,   219,    64,    65,    68,   212,
       0,     0,    31,    30,    33,    25,     0,     0,   229,    72,
      74,    71,    73,     0,   214,     0,    40,    41,     0,   215
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -155,  -155,  -155,   105,  -123,  -122,   -92,    26,  -155,  -127,
       2,    -2,  -155,  -155,   -82,  -155,  -155,  -155,  -155,  -155,
     -77,   -59,   -57,  -155,  -155,     9,  -155,  -155,  -155,  -155,
    -155,   226,   -79,   -86,   -68
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     1,     2,   115,   112,   113,   232,    93,    94,   130,
     131,   245,   234,   235,    97,    98,    99,   100,   101,   185,
     186,   187,   188,   189,   102,   246,   104,   105,   106,   206,
     207,   107,   108,   109,   134
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      96,   -60,   229,   -13,    95,   233,   129,     3,   195,   196,
     117,   103,   133,   114,   110,   111,   216,   116,   238,   239,
     208,   213,   195,   196,    89,   128,   212,   212,   195,   196,
     211,   214,   219,   221,   223,   225,   227,    91,   195,   196,
     199,   200,   201,   202,   217,   133,   236,   191,   240,   241,
     220,   222,   224,   226,   228,   199,   200,   201,   202,   201,
     202,   231,   262,   263,   237,   265,   268,   197,   198,   199,
     200,   201,   202,   197,   198,   199,   200,   201,   202,   269,
     274,   275,   264,   233,   198,   199,   200,   201,   202,   110,
     111,   -42,   -42,    96,    96,   270,   132,    95,    95,   215,
     271,   217,   272,   190,   103,   103,   278,    92,   242,   279,
     210,   210,   266,   267,   209,   209,   218,   218,   218,   218,
     218,   103,   103,   212,   259,   135,   243,   114,   244,   132,
     218,   116,   260,     0,     0,     0,   192,   193,   194,   195,
     196,     0,   237,     0,     0,     0,   230,     0,     0,     0,
     261,     0,     0,     0,     0,     0,     0,     0,     0,   117,
       0,   -60,   -60,   -13,   -13,     0,   116,     0,     0,     0,
       0,   -60,   117,   -13,   276,   277,   190,     0,     0,   116,
     133,   133,     0,     0,   197,   198,   199,   200,   201,   202,
     261,     0,     0,   203,   204,   205,   123,   124,   125,   126,
     127,    89,   128,     0,     0,    90,     0,   210,   258,     0,
       0,   209,   209,     0,    91,     0,   218,     0,   103,   103,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    -3,     0,     0,     4,     5,     6,
       7,     8,     9,    10,    11,    12,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   258,     0,     0,     0,
      95,     0,     0,     0,   132,   132,     0,   103,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,     0,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,     0,     0,     0,     0,     0,    46,    47,    48,
      49,    50,    51,    52,     0,     0,    53,    54,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    55,    56,    57,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    71,     0,    72,
      73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
      83,    84,    85,    86,    87,    88,     0,     0,     0,     0,
       0,     0,    89,     0,     0,     0,    90,     0,     0,     0,
       0,     0,     0,     0,     0,    91,     4,     5,     6,     7,
       8,     9,    10,    11,    12,     0,   247,     0,     0,     0,
       0,   248,   249,   250,   251,   252,   253,   254,   255,   118,
     119,   120,   256,   257,     0,     0,     0,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,     0,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,   273,     0,     0,     0,     0,    46,    47,    48,    49,
      50,    51,    52,     0,     0,    53,    54,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    55,    56,    57,     0,     0,     0,     0,   121,   122,
       0,     0,     0,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,     0,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,     0,   123,   124,   125,   126,
     127,    89,   128,     0,     0,    90,     0,     0,     0,     0,
       0,     0,     0,     0,    91,     4,     5,     6,     7,     8,
       9,    10,    11,    12,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,     0,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
       0,     0,     0,     0,     0,    46,    47,    48,    49,    50,
      51,    52,     0,     0,    53,    54,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      55,    56,    57,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,     0,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,     0,   123,   124,   125,   126,   127,
      89,   128,     0,     0,    90,     0,     0,     0,     0,     0,
       0,     0,     0,    91,     4,     5,     6,     7,     8,     9,
      10,    11,    12,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,     0,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    43,    44,    45,     0,
       0,     0,     0,     0,    46,    47,    48,    49,    50,    51,
      52,     0,     0,    53,    54,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    55,
      56,    57,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,     0,    72,    73,    74,    75,
      76,    77,    78,    79,    80,    81,    82,    83,    84,    85,
      86,    87,    88,     0,     0,     0,     0,     0,     0,    89,
     128,     0,     0,    90,     0,     0,     0,     0,     0,     0,
       0,     0,    91,     4,     5,     6,     7,     8,     9,    10,
      11,    12,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
       0,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    43,    44,    45,     0,     0,
     118,   119,   120,    46,    47,    48,    49,    50,    51,    52,
       0,     0,    53,    54,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    55,    56,
      57,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,     0,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    85,    86,
      87,    88,     0,     0,     0,     0,     0,     0,    89,   121,
     122,     0,    90,     0,     0,     0,     0,     0,     0,   138,
     139,    91,   141,   142,   143,   144,   145,   146,   147,     0,
     148,   -48,   -48,   -48,     0,   150,   151,   152,   153,     0,
       0,     0,     0,     0,     0,     0,     0,   123,   124,   125,
     126,   127,    89,   128,     0,   154,    90,     0,     0,     0,
       0,     0,     0,     0,     0,    91,     0,     0,     0,     0,
       0,     0,     0,   155,   156,   157,   158,   159,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   162,
     163,   164,   165,   166,   167,   168,   169,   170,   171,   172,
     173,   174,   175,   176,   177,   178,   179,   180,   181,     0,
       0,   182,   183,     0,     0,     0,     0,     0,     0,     0,
     -48,   -48,     0,     0,     0,     0,     0,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,     0,
     148,     0,     0,     0,   149,   150,   151,   152,   153,     0,
       0,     0,     0,     0,     0,     0,     0,   184,   -48,   -48,
     -48,   -48,   -48,   -48,   -48,   154,     0,   -48,     0,     0,
       0,     0,     0,     0,     0,     0,   -48,     0,     0,     0,
       0,     0,     0,   155,   156,   157,   158,   159,     0,     0,
       0,     0,     0,     0,     0,   160,   161,     0,     0,   162,
     163,   164,   165,   166,   167,   168,   169,   170,   171,   172,
     173,   174,   175,   176,   177,   178,   179,   180,   181,     0,
       0,   182,   183,     0,     0,    23,    24,    25,    26,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,     0,
       0,     0,     0,    27,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    42,
      43,    44,    45,    53,    54,     0,     0,   184,    46,    47,
      48,    49,    50,    51,    52,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    59,    60,     0,    57,    63,    64,     0,    66,
      67,     0,    69,    70,    71,    58,    72,    73,    74,     0,
       0,     0,     0,     0,    80,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    89,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    91
};

static const yytype_int16 yycheck[] =
{
       2,     0,    24,     0,     2,   132,    98,     0,   118,   119,
      96,     2,    98,    95,   160,   161,   170,    96,   160,   161,
     112,   113,   118,   119,   158,   159,   112,   113,   118,   119,
     112,   113,   118,   119,   120,   121,   122,   171,   118,   119,
     165,   166,   167,   168,   170,   131,   132,    26,   160,   161,
     118,   119,   120,   121,   122,   165,   166,   167,   168,   167,
     168,   168,   155,   158,   132,   170,   170,   163,   164,   165,
     166,   167,   168,   163,   164,   165,   166,   167,   168,    13,
     176,   177,   158,   210,   164,   165,   166,   167,   168,   160,
     161,   160,   161,    95,    96,    13,    98,    95,    96,   170,
      12,   170,    12,   175,    95,    96,   158,     2,   185,   176,
     112,   113,   235,   235,   112,   113,   118,   119,   120,   121,
     122,   112,   113,   209,   210,    99,   185,   209,   185,   131,
     132,   210,   218,    -1,    -1,    -1,   115,   116,   117,   118,
     119,    -1,   210,    -1,    -1,    -1,   168,    -1,    -1,    -1,
     218,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   245,
      -1,   160,   161,   160,   161,    -1,   245,    -1,    -1,    -1,
      -1,   170,   258,   170,   266,   267,   175,    -1,    -1,   258,
     266,   267,    -1,    -1,   163,   164,   165,   166,   167,   168,
     258,    -1,    -1,   172,   173,   174,   153,   154,   155,   156,
     157,   158,   159,    -1,    -1,   162,    -1,   209,   210,    -1,
      -1,   209,   210,    -1,   171,    -1,   218,    -1,   209,   210,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,     0,    -1,    -1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     258,    -1,    -1,    -1,   266,   267,    -1,   258,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    -1,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    -1,    -1,    -1,    -1,    -1,    73,    74,    75,
      76,    77,    78,    79,    -1,    -1,    82,    83,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   108,   109,   110,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   120,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,    -1,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,    -1,    -1,    -1,    -1,
      -1,    -1,   158,    -1,    -1,    -1,   162,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   171,     3,     4,     5,     6,
       7,     8,     9,    10,    11,    -1,   190,    -1,    -1,    -1,
      -1,   195,   196,   197,   198,   199,   200,   201,   202,    26,
      27,    28,   206,   207,    -1,    -1,    -1,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
      47,    48,    49,    -1,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,   245,    -1,    -1,    -1,    -1,    73,    74,    75,    76,
      77,    78,    79,    -1,    -1,    82,    83,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   108,   109,   110,    -1,    -1,    -1,    -1,   115,   116,
      -1,    -1,    -1,   120,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,    -1,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,    -1,   153,   154,   155,   156,
     157,   158,   159,    -1,    -1,   162,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   171,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    47,
      48,    49,    -1,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      -1,    -1,    -1,    -1,    -1,    73,    74,    75,    76,    77,
      78,    79,    -1,    -1,    82,    83,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     108,   109,   110,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   120,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,   133,    -1,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,   151,    -1,   153,   154,   155,   156,   157,
     158,   159,    -1,    -1,   162,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   171,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    34,    35,    36,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    47,    48,
      49,    -1,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    -1,
      -1,    -1,    -1,    -1,    73,    74,    75,    76,    77,    78,
      79,    -1,    -1,    82,    83,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   108,
     109,   110,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   120,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,    -1,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,    -1,    -1,    -1,    -1,    -1,    -1,   158,
     159,    -1,    -1,   162,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   171,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    34,    35,    36,    37,    38,    39,
      40,    41,    42,    43,    44,    45,    46,    47,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    -1,    -1,
      26,    27,    28,    73,    74,    75,    76,    77,    78,    79,
      -1,    -1,    82,    83,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   108,   109,
     110,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     120,   121,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,    -1,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,    -1,    -1,    -1,    -1,    -1,    -1,   158,   115,
     116,    -1,   162,    -1,    -1,    -1,    -1,    -1,    -1,    14,
      15,   171,    17,    18,    19,    20,    21,    22,    23,    -1,
      25,    26,    27,    28,    -1,    30,    31,    32,    33,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   153,   154,   155,
     156,   157,   158,   159,    -1,    50,   162,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   171,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    68,    69,    70,    71,    72,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,    -1,
      -1,   106,   107,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     115,   116,    -1,    -1,    -1,    -1,    -1,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    -1,
      25,    -1,    -1,    -1,    29,    30,    31,    32,    33,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   152,   153,   154,
     155,   156,   157,   158,   159,    50,    -1,   162,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   171,    -1,    -1,    -1,
      -1,    -1,    -1,    68,    69,    70,    71,    72,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    80,    81,    -1,    -1,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,    -1,
      -1,   106,   107,    -1,    -1,    44,    45,    46,    47,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    -1,
      -1,    -1,    -1,    48,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    64,
      65,    66,    67,    82,    83,    -1,    -1,   152,    73,    74,
      75,    76,    77,    78,    79,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   121,   122,    -1,   110,   125,   126,    -1,   128,
     129,    -1,   131,   132,   133,   120,   135,   136,   137,    -1,
      -1,    -1,    -1,    -1,   143,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   158,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   171
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,   179,   180,     0,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    34,    35,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    51,
      52,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    73,    74,    75,    76,
      77,    78,    79,    82,    83,   108,   109,   110,   120,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   158,
     162,   171,   181,   185,   186,   188,   189,   192,   193,   194,
     195,   196,   202,   203,   204,   205,   206,   209,   210,   211,
     160,   161,   182,   183,   192,   181,   210,   211,    26,    27,
      28,   115,   116,   153,   154,   155,   156,   157,   159,   184,
     187,   188,   189,   211,   212,   185,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    25,    29,
      30,    31,    32,    33,    50,    68,    69,    70,    71,    72,
      80,    81,    84,    85,    86,    87,    88,    89,    90,    91,
      92,    93,    94,    95,    96,    97,    98,    99,   100,   101,
     102,   103,   106,   107,   152,   197,   198,   199,   200,   201,
     175,    26,   115,   116,   117,   118,   119,   163,   164,   165,
     166,   167,   168,   172,   173,   174,   207,   208,   184,   188,
     189,   192,   211,   184,   192,   170,   170,   170,   189,   211,
     212,   211,   212,   211,   212,   211,   212,   211,   212,    24,
     168,   168,   184,   187,   190,   191,   211,   212,   160,   161,
     160,   161,   198,   199,   200,   189,   203,   209,   209,   209,
     209,   209,   209,   209,   209,   209,   209,   209,   189,   211,
     211,   212,   155,   158,   158,   170,   182,   183,   170,    13,
      13,    12,    12,   209,   176,   177,   184,   184,   158,   176
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_uint8 yyr1[] =
{
       0,   178,   179,   179,   180,   181,   181,   181,   181,   181,
     182,   183,   184,   184,   184,   184,   184,   184,   184,   184,
     184,   184,   184,   184,   184,   184,   185,   186,   187,   187,
     187,   187,   187,   187,   187,   187,   187,   188,   189,   190,
     190,   190,   191,   191,   191,   192,   192,   193,   193,   193,
     193,   193,   193,   193,   193,   193,   194,   195,   195,   195,
     195,   195,   195,   195,   195,   195,   195,   196,   196,   197,
     197,   197,   197,   197,   197,   198,   198,   198,   198,   199,
     199,   199,   199,   199,   199,   199,   199,   199,   199,   199,
     199,   199,   199,   199,   199,   199,   199,   199,   199,   199,
     199,   199,   199,   199,   199,   200,   200,   200,   200,   200,
     200,   200,   200,   200,   200,   200,   200,   200,   201,   202,
     202,   202,   202,   202,   202,   202,   202,   202,   202,   202,
     202,   202,   202,   202,   202,   202,   202,   202,   202,   202,
     202,   202,   202,   202,   202,   202,   203,   203,   203,   203,
     203,   203,   203,   203,   203,   203,   203,   203,   203,   203,
     203,   203,   203,   203,   203,   203,   203,   203,   203,   204,
     204,   204,   204,   204,   204,   204,   204,   204,   204,   204,
     204,   204,   204,   204,   204,   204,   204,   204,   205,   205,
     205,   205,   205,   205,   205,   205,   205,   205,   205,   205,
     205,   206,   206,   206,   206,   207,   207,   207,   207,   208,
     208,   208,   209,   209,   210,   210,   210,   210,   210,   210,
     210,   210,   210,   210,   210,   210,   211,   211,   212,   212
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     1,     0,     1,     3,     3,     3,     3,
       1,     1,     1,     1,     1,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     3,     1,     1,     1,     1,
       3,     3,     1,     3,     1,     1,     2,     1,     1,     1,
       3,     3,     1,     1,     1,     1,     2,     3,     2,     2,
       2,     2,     3,     3,     2,     2,     2,     2,     2,     3,
       1,     1,     1,     1,     3,     3,     1,     1,     0,     1,
       1,     3,     3,     3,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     4,     6,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     1,     3,     1,     3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* prog: nuf expr  */
#line 164 "grammar.y"
{
	Argusfinish_parse((yyvsp[0].blk).b);
}
#line 2219 "y.tab.c"
    break;

  case 4: /* nuf: %empty  */
#line 169 "grammar.y"
                                { (yyval.blk).q = qerr; }
#line 2225 "y.tab.c"
    break;

  case 6: /* expr: expr and term  */
#line 172 "grammar.y"
                                { Argusgen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2231 "y.tab.c"
    break;

  case 7: /* expr: expr and id  */
#line 173 "grammar.y"
                                { Argusgen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2237 "y.tab.c"
    break;

  case 8: /* expr: expr or term  */
#line 174 "grammar.y"
                                { Argusgen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2243 "y.tab.c"
    break;

  case 9: /* expr: expr or id  */
#line 175 "grammar.y"
                                { Argusgen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2249 "y.tab.c"
    break;

  case 10: /* and: AND  */
#line 177 "grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2255 "y.tab.c"
    break;

  case 11: /* or: OR  */
#line 179 "grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2261 "y.tab.c"
    break;

  case 13: /* id: pnum  */
#line 182 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-1].blk).q, Q_EQUAL); }
#line 2267 "y.tab.c"
    break;

  case 14: /* id: fnum  */
#line 183 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-1].blk).q, Q_EQUAL); }
#line 2273 "y.tab.c"
    break;

  case 15: /* id: LESS pnum  */
#line 185 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-2].blk).q, Q_LESS); }
#line 2279 "y.tab.c"
    break;

  case 16: /* id: GREATER pnum  */
#line 186 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-2].blk).q, Q_GREATER); }
#line 2285 "y.tab.c"
    break;

  case 17: /* id: EQUAL pnum  */
#line 187 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-2].blk).q, Q_EQUAL); }
#line 2291 "y.tab.c"
    break;

  case 18: /* id: GEQ pnum  */
#line 188 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-2].blk).q, Q_GEQ); }
#line 2297 "y.tab.c"
    break;

  case 19: /* id: LEQ pnum  */
#line 189 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-2].blk).q, Q_LEQ); }
#line 2303 "y.tab.c"
    break;

  case 20: /* id: LESS fnum  */
#line 191 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-2].blk).q, Q_LESS); }
#line 2309 "y.tab.c"
    break;

  case 21: /* id: GREATER fnum  */
#line 192 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-2].blk).q, Q_GREATER); }
#line 2315 "y.tab.c"
    break;

  case 22: /* id: EQUAL fnum  */
#line 193 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-2].blk).q, Q_EQUAL); }
#line 2321 "y.tab.c"
    break;

  case 23: /* id: GEQ fnum  */
#line 194 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-2].blk).q, Q_GEQ); }
#line 2327 "y.tab.c"
    break;

  case 24: /* id: LEQ fnum  */
#line 195 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-2].blk).q, Q_LEQ); }
#line 2333 "y.tab.c"
    break;

  case 25: /* id: paren pid ')'  */
#line 197 "grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2339 "y.tab.c"
    break;

  case 26: /* tid: tname  */
#line 199 "grammar.y"
                                { (yyval.blk).b = Argusgen_tcode((yyvsp[0].i), (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2345 "y.tab.c"
    break;

  case 27: /* oid: oname  */
#line 201 "grammar.y"
                                { (yyval.blk).b = Argusgen_ocode((yyvsp[0].i), (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2351 "y.tab.c"
    break;

  case 28: /* nid: ID  */
#line 203 "grammar.y"
                                { (yyval.blk).b = Argusgen_scode((yyvsp[0].s), (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2357 "y.tab.c"
    break;

  case 29: /* nid: STRING  */
#line 204 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-1].blk).q; (yyval.blk).q.type = Q_STRING;
                                  (yyval.blk).b = Argusgen_scode((yyvsp[0].s), (yyval.blk).q); }
#line 2364 "y.tab.c"
    break;

  case 30: /* nid: HIDV4 '/' NUM  */
#line 206 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-3].blk).q; (yyval.blk).q.type = Q_IPV4;
                                  (yyval.blk).b = Argusgen_mcode((yyvsp[-2].s), NULL, (yyvsp[0].i), (yyval.blk).q); }
#line 2371 "y.tab.c"
    break;

  case 31: /* nid: HIDV4 AMASK HIDV4  */
#line 208 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-3].blk).q; (yyval.blk).q.type = Q_IPV4;
                                  (yyval.blk).b = Argusgen_mcode((yyvsp[-2].s), (char *)(yyvsp[0].s), 0, (yyval.blk).q); }
#line 2378 "y.tab.c"
    break;

  case 32: /* nid: HIDV4  */
#line 210 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-1].blk).q; (yyval.blk).q.type = Q_IPV4;
                                  (yyval.blk).b = Argusgen_ncode((yyvsp[0].s), 0, (yyval.blk).q, Q_EQUAL); }
#line 2385 "y.tab.c"
    break;

  case 33: /* nid: HIDV6 '/' NUM  */
#line 212 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-3].blk).q; (yyval.blk).q.type = Q_IPV6;
                                  (yyval.blk).b = Argusgen_mcode((yyvsp[-2].s), NULL, (yyvsp[0].i), (yyval.blk).q); }
#line 2392 "y.tab.c"
    break;

  case 34: /* nid: HIDV6  */
#line 214 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-1].blk).q; (yyval.blk).q.type = Q_IPV6;
                                  (yyval.blk).b = Argusgen_ncode((yyvsp[0].s), 0, (yyval.blk).q, Q_EQUAL); }
#line 2399 "y.tab.c"
    break;

  case 35: /* nid: EID  */
#line 216 "grammar.y"
                                { (yyval.blk).q = (yyvsp[-1].blk).q; (yyval.blk).q.type = Q_IPV6;
				  (yyval.blk).b = Argusgen_ecode((yyvsp[0].e), (yyval.blk).q); }
#line 2406 "y.tab.c"
    break;

  case 36: /* nid: not id  */
#line 218 "grammar.y"
                                { Argusgen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2412 "y.tab.c"
    break;

  case 37: /* not: '!'  */
#line 220 "grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2418 "y.tab.c"
    break;

  case 38: /* paren: '('  */
#line 222 "grammar.y"
                                { (yyval.blk) = (yyvsp[-1].blk); }
#line 2424 "y.tab.c"
    break;

  case 40: /* pid: qid and id  */
#line 225 "grammar.y"
                                { Argusgen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2430 "y.tab.c"
    break;

  case 41: /* pid: qid or id  */
#line 226 "grammar.y"
                                { Argusgen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2436 "y.tab.c"
    break;

  case 42: /* qid: pnum  */
#line 228 "grammar.y"
                                { (yyval.blk).b = Argusgen_ncode(NULL, (int)(yyvsp[0].i), (yyval.blk).q = (yyvsp[-1].blk).q, Q_EQUAL); }
#line 2442 "y.tab.c"
    break;

  case 43: /* qid: fnum  */
#line 229 "grammar.y"
                                { (yyval.blk).b = Argusgen_fcode(NULL, (float)(yyvsp[0].f), (yyval.blk).q = (yyvsp[-1].blk).q, Q_EQUAL); }
#line 2448 "y.tab.c"
    break;

  case 46: /* term: not term  */
#line 233 "grammar.y"
                                { Argusgen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2454 "y.tab.c"
    break;

  case 47: /* head: pqual dqual aqual  */
#line 235 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-2].i), (yyvsp[-1].i), (yyvsp[0].i)); }
#line 2460 "y.tab.c"
    break;

  case 48: /* head: pqual dqual  */
#line 236 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), (yyvsp[0].i), Q_DEFAULT); }
#line 2466 "y.tab.c"
    break;

  case 49: /* head: pqual aqual  */
#line 237 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2472 "y.tab.c"
    break;

  case 50: /* head: pqual iqual  */
#line 238 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); (yyval.blk).q.type = Q_INTEGER; }
#line 2478 "y.tab.c"
    break;

  case 51: /* head: pqual fqual  */
#line 239 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].f)); (yyval.blk).q.type = Q_FLOAT; }
#line 2484 "y.tab.c"
    break;

  case 52: /* head: pqual dqual iqual  */
#line 240 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-2].i), (yyvsp[-1].i), (yyvsp[0].i)); (yyval.blk).q.type = Q_INTEGER; }
#line 2490 "y.tab.c"
    break;

  case 53: /* head: pqual dqual fqual  */
#line 241 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-2].i), (yyvsp[-1].i), (yyvsp[0].f)); (yyval.blk).q.type = Q_FLOAT; }
#line 2496 "y.tab.c"
    break;

  case 54: /* head: pqual PROTO  */
#line 242 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTO); }
#line 2502 "y.tab.c"
    break;

  case 55: /* head: pqual ndaqual  */
#line 243 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2508 "y.tab.c"
    break;

  case 56: /* thead: pqual dqual  */
#line 246 "grammar.y"
                                { QSET((yyval.blk).q, (yyvsp[-1].i), (yyvsp[0].i), Q_DEFAULT); }
#line 2514 "y.tab.c"
    break;

  case 57: /* rterm: head id  */
#line 249 "grammar.y"
                                { (yyval.blk) = (yyvsp[0].blk); }
#line 2520 "y.tab.c"
    break;

  case 58: /* rterm: thead tid  */
#line 250 "grammar.y"
                                { (yyval.blk) = (yyvsp[0].blk); }
#line 2526 "y.tab.c"
    break;

  case 59: /* rterm: paren expr ')'  */
#line 251 "grammar.y"
                                { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = (yyvsp[-2].blk).q; }
#line 2532 "y.tab.c"
    break;

  case 60: /* rterm: pname  */
#line 252 "grammar.y"
                                { (yyval.blk).b = Argusgen_proto_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2538 "y.tab.c"
    break;

  case 61: /* rterm: sname  */
#line 253 "grammar.y"
                                { (yyval.blk).b = Argusgen_proto_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2544 "y.tab.c"
    break;

  case 62: /* rterm: tid  */
#line 254 "grammar.y"
                                { (yyval.blk) = (yyvsp[0].blk); }
#line 2550 "y.tab.c"
    break;

  case 63: /* rterm: oid  */
#line 255 "grammar.y"
                                { (yyval.blk) = (yyvsp[0].blk); }
#line 2556 "y.tab.c"
    break;

  case 64: /* rterm: arth relop arth  */
#line 256 "grammar.y"
                                { (yyval.blk).b = Argusgen_relation((yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 0); (yyval.blk).q = qerr; }
#line 2562 "y.tab.c"
    break;

  case 65: /* rterm: arth irelop arth  */
#line 257 "grammar.y"
                                { (yyval.blk).b = Argusgen_relation((yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 1); (yyval.blk).q = qerr; }
#line 2568 "y.tab.c"
    break;

  case 66: /* rterm: other  */
#line 258 "grammar.y"
                                { (yyval.blk).b = (yyvsp[0].rblk); (yyval.blk).q = qerr; }
#line 2574 "y.tab.c"
    break;

  case 68: /* pqual: %empty  */
#line 263 "grammar.y"
                                { (yyval.i) = Q_DEFAULT; }
#line 2580 "y.tab.c"
    break;

  case 69: /* dqual: SRC  */
#line 266 "grammar.y"
                                { (yyval.i) = Q_SRC; }
#line 2586 "y.tab.c"
    break;

  case 70: /* dqual: DST  */
#line 267 "grammar.y"
                                { (yyval.i) = Q_DST; }
#line 2592 "y.tab.c"
    break;

  case 71: /* dqual: SRC OR DST  */
#line 268 "grammar.y"
                                { (yyval.i) = Q_OR; }
#line 2598 "y.tab.c"
    break;

  case 72: /* dqual: DST OR SRC  */
#line 269 "grammar.y"
                                { (yyval.i) = Q_OR; }
#line 2604 "y.tab.c"
    break;

  case 73: /* dqual: SRC AND DST  */
#line 270 "grammar.y"
                                { (yyval.i) = Q_AND; }
#line 2610 "y.tab.c"
    break;

  case 74: /* dqual: DST AND SRC  */
#line 271 "grammar.y"
                                { (yyval.i) = Q_AND; }
#line 2616 "y.tab.c"
    break;

  case 75: /* aqual: HOST  */
#line 274 "grammar.y"
                                { (yyval.i) = Q_HOST; }
#line 2622 "y.tab.c"
    break;

  case 76: /* aqual: SRCID  */
#line 275 "grammar.y"
                                { (yyval.i) = Q_SRCID; }
#line 2628 "y.tab.c"
    break;

  case 77: /* aqual: INODE  */
#line 276 "grammar.y"
                                { (yyval.i) = Q_INODE; }
#line 2634 "y.tab.c"
    break;

  case 78: /* aqual: NET  */
#line 277 "grammar.y"
                                { (yyval.i) = Q_NET; }
#line 2640 "y.tab.c"
    break;

  case 79: /* iqual: PORT  */
#line 280 "grammar.y"
                                { (yyval.i) = Q_PORT; }
#line 2646 "y.tab.c"
    break;

  case 80: /* iqual: IPID  */
#line 281 "grammar.y"
                                { (yyval.i) = Q_IPID; }
#line 2652 "y.tab.c"
    break;

  case 81: /* iqual: TTL  */
#line 282 "grammar.y"
                                { (yyval.i) = Q_TTL; }
#line 2658 "y.tab.c"
    break;

  case 82: /* iqual: TOS  */
#line 283 "grammar.y"
                                { (yyval.i) = Q_TOS; }
#line 2664 "y.tab.c"
    break;

  case 83: /* iqual: DSB  */
#line 284 "grammar.y"
                                { (yyval.i) = Q_DSB; }
#line 2670 "y.tab.c"
    break;

  case 84: /* iqual: CO  */
#line 285 "grammar.y"
                                { (yyval.i) = Q_CO; }
#line 2676 "y.tab.c"
    break;

  case 85: /* iqual: ASN  */
#line 286 "grammar.y"
                                { (yyval.i) = Q_ASN; }
#line 2682 "y.tab.c"
    break;

  case 86: /* iqual: VID  */
#line 287 "grammar.y"
                                { (yyval.i) = Q_VID; }
#line 2688 "y.tab.c"
    break;

  case 87: /* iqual: VPRI  */
#line 288 "grammar.y"
                                { (yyval.i) = Q_VPRI; }
#line 2694 "y.tab.c"
    break;

  case 88: /* iqual: MPLSID  */
#line 289 "grammar.y"
                                { (yyval.i) = Q_MPLSID; }
#line 2700 "y.tab.c"
    break;

  case 89: /* iqual: BYTE  */
#line 290 "grammar.y"
                                { (yyval.i) = Q_BYTE; }
#line 2706 "y.tab.c"
    break;

  case 90: /* iqual: APPBYTE  */
#line 291 "grammar.y"
                                { (yyval.i) = Q_APPBYTE; }
#line 2712 "y.tab.c"
    break;

  case 91: /* iqual: PKT  */
#line 292 "grammar.y"
                                { (yyval.i) = Q_PKT; }
#line 2718 "y.tab.c"
    break;

  case 92: /* iqual: TRANS  */
#line 293 "grammar.y"
                                { (yyval.i) = Q_TRANS; }
#line 2724 "y.tab.c"
    break;

  case 93: /* iqual: TCPRTT  */
#line 294 "grammar.y"
                                { (yyval.i) = Q_TCPRTT; }
#line 2730 "y.tab.c"
    break;

  case 94: /* iqual: TCPBASE  */
#line 295 "grammar.y"
                                { (yyval.i) = Q_TCPBASE; }
#line 2736 "y.tab.c"
    break;

  case 95: /* iqual: LOSS  */
#line 296 "grammar.y"
                                { (yyval.i) = Q_LOSS; }
#line 2742 "y.tab.c"
    break;

  case 96: /* iqual: GAP  */
#line 297 "grammar.y"
                                { (yyval.i) = Q_GAP; }
#line 2748 "y.tab.c"
    break;

  case 97: /* iqual: DUP  */
#line 298 "grammar.y"
                                { (yyval.i) = Q_DUP; }
#line 2754 "y.tab.c"
    break;

  case 98: /* iqual: SPI  */
#line 299 "grammar.y"
                                { (yyval.i) = Q_SPI; }
#line 2760 "y.tab.c"
    break;

  case 99: /* iqual: ENCAPS  */
#line 300 "grammar.y"
                                { (yyval.i) = Q_ENCAPS; }
#line 2766 "y.tab.c"
    break;

  case 100: /* iqual: DELTADUR  */
#line 301 "grammar.y"
                                { (yyval.i) = Q_DELTADUR; }
#line 2772 "y.tab.c"
    break;

  case 101: /* iqual: DELTASTART  */
#line 302 "grammar.y"
                                { (yyval.i) = Q_DELTASTART; }
#line 2778 "y.tab.c"
    break;

  case 102: /* iqual: DELTALAST  */
#line 303 "grammar.y"
                                { (yyval.i) = Q_DELTALAST; }
#line 2784 "y.tab.c"
    break;

  case 103: /* iqual: NSTROKE  */
#line 304 "grammar.y"
                                { (yyval.i) = Q_NSTROKE; }
#line 2790 "y.tab.c"
    break;

  case 104: /* iqual: SEQ  */
#line 305 "grammar.y"
                                { (yyval.i) = Q_SEQ; }
#line 2796 "y.tab.c"
    break;

  case 105: /* fqual: DUR  */
#line 308 "grammar.y"
                                { (yyval.f) = Q_DUR; }
#line 2802 "y.tab.c"
    break;

  case 106: /* fqual: AVGDUR  */
#line 309 "grammar.y"
                                { (yyval.f) = Q_AVGDUR; }
#line 2808 "y.tab.c"
    break;

  case 107: /* fqual: INTER  */
#line 310 "grammar.y"
                                { (yyval.f) = Q_INTER; }
#line 2814 "y.tab.c"
    break;

  case 108: /* fqual: INTERACTIVE  */
#line 311 "grammar.y"
                                { (yyval.f) = Q_INTERACTIVE; }
#line 2820 "y.tab.c"
    break;

  case 109: /* fqual: INTERIDLE  */
#line 312 "grammar.y"
                                { (yyval.f) = Q_INTERIDLE; }
#line 2826 "y.tab.c"
    break;

  case 110: /* fqual: JITTER  */
#line 313 "grammar.y"
                                { (yyval.f) = Q_JITTER; }
#line 2832 "y.tab.c"
    break;

  case 111: /* fqual: JITTERACTIVE  */
#line 314 "grammar.y"
                                { (yyval.f) = Q_JITTERACTIVE; }
#line 2838 "y.tab.c"
    break;

  case 112: /* fqual: JITTERIDLE  */
#line 315 "grammar.y"
                                { (yyval.f) = Q_JITTERIDLE; }
#line 2844 "y.tab.c"
    break;

  case 113: /* fqual: RATE  */
#line 316 "grammar.y"
                                { (yyval.f) = Q_RATE; }
#line 2850 "y.tab.c"
    break;

  case 114: /* fqual: LOAD  */
#line 317 "grammar.y"
                                { (yyval.f) = Q_LOAD; }
#line 2856 "y.tab.c"
    break;

  case 115: /* fqual: PLOSS  */
#line 318 "grammar.y"
                                { (yyval.f) = Q_PLOSS; }
#line 2862 "y.tab.c"
    break;

  case 116: /* fqual: ABR  */
#line 319 "grammar.y"
                                { (yyval.f) = Q_PCR; }
#line 2868 "y.tab.c"
    break;

  case 117: /* fqual: PCR  */
#line 320 "grammar.y"
                                { (yyval.f) = Q_PCR; }
#line 2874 "y.tab.c"
    break;

  case 118: /* ndaqual: GATEWAY  */
#line 323 "grammar.y"
                                { (yyval.i) = Q_GATEWAY; }
#line 2880 "y.tab.c"
    break;

  case 119: /* sname: START  */
#line 326 "grammar.y"
                                { (yyval.i) = Q_START; }
#line 2886 "y.tab.c"
    break;

  case 120: /* sname: STOP  */
#line 327 "grammar.y"
                                { (yyval.i) = Q_STOP; }
#line 2892 "y.tab.c"
    break;

  case 121: /* sname: STATUS  */
#line 328 "grammar.y"
                                { (yyval.i) = Q_STATUS; }
#line 2898 "y.tab.c"
    break;

  case 122: /* sname: SHUTDOWN  */
#line 329 "grammar.y"
                                { (yyval.i) = Q_SHUTDOWN; }
#line 2904 "y.tab.c"
    break;

  case 123: /* sname: ERROR  */
#line 330 "grammar.y"
                                { (yyval.i) = Q_ERROR; }
#line 2910 "y.tab.c"
    break;

  case 124: /* sname: MAN  */
#line 331 "grammar.y"
                                { (yyval.i) = Q_MAN; }
#line 2916 "y.tab.c"
    break;

  case 125: /* sname: FAR  */
#line 332 "grammar.y"
                                { (yyval.i) = Q_FAR; }
#line 2922 "y.tab.c"
    break;

  case 126: /* sname: EVENT  */
#line 333 "grammar.y"
                                { (yyval.i) = Q_EVENT; }
#line 2928 "y.tab.c"
    break;

  case 127: /* sname: INDEX  */
#line 334 "grammar.y"
                                { (yyval.i) = Q_INDEX; }
#line 2934 "y.tab.c"
    break;

  case 128: /* sname: SVC  */
#line 335 "grammar.y"
                                { (yyval.i) = Q_SVC; }
#line 2940 "y.tab.c"
    break;

  case 129: /* sname: NORMAL  */
#line 336 "grammar.y"
                                { (yyval.i) = Q_NORMAL; }
#line 2946 "y.tab.c"
    break;

  case 130: /* sname: WAIT  */
#line 337 "grammar.y"
                                { (yyval.i) = Q_WAIT; }
#line 2952 "y.tab.c"
    break;

  case 131: /* sname: SYNACK  */
#line 338 "grammar.y"
                                { (yyval.i) = Q_SYNACK; }
#line 2958 "y.tab.c"
    break;

  case 132: /* sname: FINACK  */
#line 339 "grammar.y"
                                { (yyval.i) = Q_FINACK; }
#line 2964 "y.tab.c"
    break;

  case 133: /* sname: ESTABLISHED  */
#line 340 "grammar.y"
                                { (yyval.i) = Q_ESTABLISHED; }
#line 2970 "y.tab.c"
    break;

  case 134: /* sname: CONNECTED  */
#line 341 "grammar.y"
                                { (yyval.i) = Q_CONNECTED; }
#line 2976 "y.tab.c"
    break;

  case 135: /* sname: CORRELATED  */
#line 342 "grammar.y"
                                { (yyval.i) = Q_CORRELATED; }
#line 2982 "y.tab.c"
    break;

  case 136: /* sname: TIMEDOUT  */
#line 343 "grammar.y"
                                { (yyval.i) = Q_TIMEDOUT; }
#line 2988 "y.tab.c"
    break;

  case 137: /* sname: ICMPMAP  */
#line 344 "grammar.y"
                                { (yyval.i) = Q_ICMPMAP; }
#line 2994 "y.tab.c"
    break;

  case 138: /* sname: ICMPECHO  */
#line 345 "grammar.y"
                                { (yyval.i) = Q_ECHO; }
#line 3000 "y.tab.c"
    break;

  case 139: /* sname: UNREACH  */
#line 346 "grammar.y"
                                { (yyval.i) = Q_UNREACH; }
#line 3006 "y.tab.c"
    break;

  case 140: /* sname: REDIRECT  */
#line 347 "grammar.y"
                                { (yyval.i) = Q_REDIRECT; }
#line 3012 "y.tab.c"
    break;

  case 141: /* sname: TIMEXED  */
#line 348 "grammar.y"
                                { (yyval.i) = Q_TIMEXED; }
#line 3018 "y.tab.c"
    break;

  case 142: /* sname: RTR  */
#line 349 "grammar.y"
                                { (yyval.i) = Q_RTR; }
#line 3024 "y.tab.c"
    break;

  case 143: /* sname: MBR  */
#line 350 "grammar.y"
                                { (yyval.i) = Q_MBR; }
#line 3030 "y.tab.c"
    break;

  case 144: /* sname: LVG  */
#line 351 "grammar.y"
                                { (yyval.i) = Q_LVG; }
#line 3036 "y.tab.c"
    break;

  case 145: /* sname: COCODE  */
#line 352 "grammar.y"
                                { (yyval.i) = Q_COCODE; }
#line 3042 "y.tab.c"
    break;

  case 146: /* pname: LINK  */
#line 355 "grammar.y"
                                { (yyval.i) = Q_LINK; }
#line 3048 "y.tab.c"
    break;

  case 147: /* pname: ETHER  */
#line 356 "grammar.y"
                                { (yyval.i) = Q_ETHER; }
#line 3054 "y.tab.c"
    break;

  case 148: /* pname: IP  */
#line 357 "grammar.y"
                                { (yyval.i) = Q_IP; }
#line 3060 "y.tab.c"
    break;

  case 149: /* pname: IPV4  */
#line 358 "grammar.y"
                                { (yyval.i) = Q_IPV4; }
#line 3066 "y.tab.c"
    break;

  case 150: /* pname: IPV6  */
#line 359 "grammar.y"
                                { (yyval.i) = Q_IPV6; }
#line 3072 "y.tab.c"
    break;

  case 151: /* pname: ARP  */
#line 360 "grammar.y"
                                { (yyval.i) = Q_ARP; }
#line 3078 "y.tab.c"
    break;

  case 152: /* pname: RARP  */
#line 361 "grammar.y"
                                { (yyval.i) = Q_RARP; }
#line 3084 "y.tab.c"
    break;

  case 153: /* pname: ESP  */
#line 362 "grammar.y"
                                { (yyval.i) = Q_ESP; }
#line 3090 "y.tab.c"
    break;

  case 154: /* pname: RTP  */
#line 363 "grammar.y"
                                { (yyval.i) = Q_RTP; }
#line 3096 "y.tab.c"
    break;

  case 155: /* pname: RTCP  */
#line 364 "grammar.y"
                                { (yyval.i) = Q_RTCP; }
#line 3102 "y.tab.c"
    break;

  case 156: /* pname: TCP  */
#line 365 "grammar.y"
                                { (yyval.i) = Q_TCP; }
#line 3108 "y.tab.c"
    break;

  case 157: /* pname: UDP  */
#line 366 "grammar.y"
                                { (yyval.i) = Q_UDP; }
#line 3114 "y.tab.c"
    break;

  case 158: /* pname: ICMP  */
#line 367 "grammar.y"
                                { (yyval.i) = Q_ICMP; }
#line 3120 "y.tab.c"
    break;

  case 159: /* pname: IGMP  */
#line 368 "grammar.y"
                                { (yyval.i) = Q_IGMP; }
#line 3126 "y.tab.c"
    break;

  case 160: /* pname: MPLS  */
#line 369 "grammar.y"
                                { (yyval.i) = Q_MPLS; }
#line 3132 "y.tab.c"
    break;

  case 161: /* pname: ISIS  */
#line 370 "grammar.y"
                                { (yyval.i) = Q_ISIS; }
#line 3138 "y.tab.c"
    break;

  case 162: /* pname: VLAN  */
#line 371 "grammar.y"
                                { (yyval.i) = Q_VLAN; }
#line 3144 "y.tab.c"
    break;

  case 163: /* pname: UDT  */
#line 372 "grammar.y"
                                { (yyval.i) = Q_UDT; }
#line 3150 "y.tab.c"
    break;

  case 164: /* pname: ANON  */
#line 373 "grammar.y"
                                { (yyval.i) = Q_ANON; }
#line 3156 "y.tab.c"
    break;

  case 165: /* pname: DECNET  */
#line 374 "grammar.y"
                                { (yyval.i) = Q_DECNET; }
#line 3162 "y.tab.c"
    break;

  case 166: /* pname: LAT  */
#line 375 "grammar.y"
                                { (yyval.i) = Q_LAT; }
#line 3168 "y.tab.c"
    break;

  case 167: /* pname: MOPDL  */
#line 376 "grammar.y"
                                { (yyval.i) = Q_MOPDL; }
#line 3174 "y.tab.c"
    break;

  case 168: /* pname: MOPRC  */
#line 377 "grammar.y"
                                { (yyval.i) = Q_MOPRC; }
#line 3180 "y.tab.c"
    break;

  case 169: /* tname: OUTOFORDER  */
#line 380 "grammar.y"
                                { (yyval.i) = Q_OUTOFORDER; }
#line 3186 "y.tab.c"
    break;

  case 170: /* tname: RETRANS  */
#line 381 "grammar.y"
                                { (yyval.i) = Q_RETRANS; }
#line 3192 "y.tab.c"
    break;

  case 171: /* tname: WINSHUT  */
#line 382 "grammar.y"
                                { (yyval.i) = Q_WINSHUT; }
#line 3198 "y.tab.c"
    break;

  case 172: /* tname: SYN  */
#line 383 "grammar.y"
                                { (yyval.i) = Q_SYN; }
#line 3204 "y.tab.c"
    break;

  case 173: /* tname: FIN  */
#line 384 "grammar.y"
                                { (yyval.i) = Q_FIN; }
#line 3210 "y.tab.c"
    break;

  case 174: /* tname: RESET  */
#line 385 "grammar.y"
                                { (yyval.i) = Q_RESET; }
#line 3216 "y.tab.c"
    break;

  case 175: /* tname: ACK  */
#line 386 "grammar.y"
                                { (yyval.i) = Q_ACK; }
#line 3222 "y.tab.c"
    break;

  case 176: /* tname: PUSH  */
#line 387 "grammar.y"
                                { (yyval.i) = Q_PUSH; }
#line 3228 "y.tab.c"
    break;

  case 177: /* tname: URGENT  */
#line 388 "grammar.y"
                                { (yyval.i) = Q_URGENT; }
#line 3234 "y.tab.c"
    break;

  case 178: /* tname: CWR  */
#line 389 "grammar.y"
                                { (yyval.i) = Q_CWR; }
#line 3240 "y.tab.c"
    break;

  case 179: /* tname: ECE  */
#line 390 "grammar.y"
                                { (yyval.i) = Q_ECE; }
#line 3246 "y.tab.c"
    break;

  case 180: /* tname: FRAG  */
#line 391 "grammar.y"
                                { (yyval.i) = Q_FRAG; }
#line 3252 "y.tab.c"
    break;

  case 181: /* tname: FRAG_ONLY  */
#line 392 "grammar.y"
                                { (yyval.i) = Q_FRAG_ONLY; }
#line 3258 "y.tab.c"
    break;

  case 182: /* tname: ECN  */
#line 393 "grammar.y"
                                { (yyval.i) = Q_ECN; }
#line 3264 "y.tab.c"
    break;

  case 183: /* tname: MULTIPATH  */
#line 394 "grammar.y"
                                { (yyval.i) = Q_MULTIPATH; }
#line 3270 "y.tab.c"
    break;

  case 184: /* tname: HELLO  */
#line 395 "grammar.y"
                                { (yyval.i) = Q_HELLO; }
#line 3276 "y.tab.c"
    break;

  case 185: /* tname: LSP  */
#line 396 "grammar.y"
                                { (yyval.i) = Q_LSP; }
#line 3282 "y.tab.c"
    break;

  case 186: /* tname: CSNP  */
#line 397 "grammar.y"
                                { (yyval.i) = Q_CSNP; }
#line 3288 "y.tab.c"
    break;

  case 187: /* tname: PSNP  */
#line 398 "grammar.y"
                                { (yyval.i) = Q_PSNP; }
#line 3294 "y.tab.c"
    break;

  case 188: /* oname: TCPOPT  */
#line 400 "grammar.y"
                                { (yyval.i) = Q_TCPOPT; }
#line 3300 "y.tab.c"
    break;

  case 189: /* oname: MSS  */
#line 401 "grammar.y"
                                { (yyval.i) = Q_MSS; }
#line 3306 "y.tab.c"
    break;

  case 190: /* oname: WSCALE  */
#line 402 "grammar.y"
                                { (yyval.i) = Q_WSCALE; }
#line 3312 "y.tab.c"
    break;

  case 191: /* oname: SELECTIVEACKOK  */
#line 403 "grammar.y"
                                { (yyval.i) = Q_SELECTIVEACKOK; }
#line 3318 "y.tab.c"
    break;

  case 192: /* oname: SELECTIVEACK  */
#line 404 "grammar.y"
                                { (yyval.i) = Q_SELECTIVEACK; }
#line 3324 "y.tab.c"
    break;

  case 193: /* oname: TCPECHO  */
#line 405 "grammar.y"
                                { (yyval.i) = Q_TCPECHO; }
#line 3330 "y.tab.c"
    break;

  case 194: /* oname: TCPECHOREPLY  */
#line 406 "grammar.y"
                                { (yyval.i) = Q_TCPECHOREPLY; }
#line 3336 "y.tab.c"
    break;

  case 195: /* oname: TCPTIMESTAMP  */
#line 407 "grammar.y"
                                { (yyval.i) = Q_TCPTIMESTAMP; }
#line 3342 "y.tab.c"
    break;

  case 196: /* oname: TCPCC  */
#line 408 "grammar.y"
                                { (yyval.i) = Q_TCPCC; }
#line 3348 "y.tab.c"
    break;

  case 197: /* oname: TCPCCNEW  */
#line 409 "grammar.y"
                                { (yyval.i) = Q_TCPCCNEW; }
#line 3354 "y.tab.c"
    break;

  case 198: /* oname: TCPCCECHO  */
#line 410 "grammar.y"
                                { (yyval.i) = Q_TCPCCECHO; }
#line 3360 "y.tab.c"
    break;

  case 199: /* oname: SECN  */
#line 411 "grammar.y"
                                { (yyval.i) = Q_SECN; }
#line 3366 "y.tab.c"
    break;

  case 200: /* oname: DECN  */
#line 412 "grammar.y"
                                { (yyval.i) = Q_DECN; }
#line 3372 "y.tab.c"
    break;

  case 201: /* other: pqual TK_BROADCAST  */
#line 415 "grammar.y"
                                { (yyval.rblk) = Argusgen_broadcast((yyvsp[-1].i)); }
#line 3378 "y.tab.c"
    break;

  case 202: /* other: pqual TK_MULTICAST  */
#line 416 "grammar.y"
                                { (yyval.rblk) = Argusgen_multicast((yyvsp[-1].i)); }
#line 3384 "y.tab.c"
    break;

  case 203: /* other: INBOUND  */
#line 417 "grammar.y"
                                { (yyval.rblk) = Argusgen_inbound(0); }
#line 3390 "y.tab.c"
    break;

  case 204: /* other: OUTBOUND  */
#line 418 "grammar.y"
                                { (yyval.rblk) = Argusgen_inbound(1); }
#line 3396 "y.tab.c"
    break;

  case 205: /* relop: '>'  */
#line 420 "grammar.y"
                                { (yyval.i) = NFF_JGT; }
#line 3402 "y.tab.c"
    break;

  case 206: /* relop: GEQ  */
#line 421 "grammar.y"
                                { (yyval.i) = NFF_JGE; }
#line 3408 "y.tab.c"
    break;

  case 207: /* relop: '='  */
#line 422 "grammar.y"
                                { (yyval.i) = NFF_JEQ; }
#line 3414 "y.tab.c"
    break;

  case 208: /* relop: EQUAL  */
#line 423 "grammar.y"
                                { (yyval.i) = NFF_JEQ; }
#line 3420 "y.tab.c"
    break;

  case 209: /* irelop: LEQ  */
#line 425 "grammar.y"
                                { (yyval.i) = NFF_JGT; }
#line 3426 "y.tab.c"
    break;

  case 210: /* irelop: '<'  */
#line 426 "grammar.y"
                                { (yyval.i) = NFF_JGE; }
#line 3432 "y.tab.c"
    break;

  case 211: /* irelop: NEQ  */
#line 427 "grammar.y"
                                { (yyval.i) = NFF_JEQ; }
#line 3438 "y.tab.c"
    break;

  case 212: /* arth: pnum  */
#line 429 "grammar.y"
                                { (yyval.a) = ArgusLoadI((yyvsp[0].i)); }
#line 3444 "y.tab.c"
    break;

  case 214: /* narth: pname '[' arth ']'  */
#line 432 "grammar.y"
                                        { (yyval.a) = ArgusLoad((yyvsp[-3].i), (yyvsp[-1].a), 1); }
#line 3450 "y.tab.c"
    break;

  case 215: /* narth: pname '[' arth ':' NUM ']'  */
#line 433 "grammar.y"
                                        { (yyval.a) = ArgusLoad((yyvsp[-5].i), (yyvsp[-3].a), (yyvsp[-1].i)); }
#line 3456 "y.tab.c"
    break;

  case 216: /* narth: arth '+' arth  */
#line 434 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_ADD, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3462 "y.tab.c"
    break;

  case 217: /* narth: arth '-' arth  */
#line 435 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_SUB, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3468 "y.tab.c"
    break;

  case 218: /* narth: arth '*' arth  */
#line 436 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_MUL, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3474 "y.tab.c"
    break;

  case 219: /* narth: arth '/' arth  */
#line 437 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_DIV, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3480 "y.tab.c"
    break;

  case 220: /* narth: arth '&' arth  */
#line 438 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_AND, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3486 "y.tab.c"
    break;

  case 221: /* narth: arth '|' arth  */
#line 439 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_OR, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3492 "y.tab.c"
    break;

  case 222: /* narth: arth LSH arth  */
#line 440 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_LSH, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3498 "y.tab.c"
    break;

  case 223: /* narth: arth RSH arth  */
#line 441 "grammar.y"
                                        { (yyval.a) = ArgusArth(NFF_RSH, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3504 "y.tab.c"
    break;

  case 224: /* narth: paren narth ')'  */
#line 442 "grammar.y"
                                        { (yyval.a) = (yyvsp[-1].a); }
#line 3510 "y.tab.c"
    break;

  case 225: /* narth: LEN  */
#line 443 "grammar.y"
                                        { (yyval.a) = ArgusLoadLen(); }
#line 3516 "y.tab.c"
    break;

  case 227: /* pnum: paren pnum ')'  */
#line 446 "grammar.y"
                                { (yyval.i) = (yyvsp[-1].i); }
#line 3522 "y.tab.c"
    break;

  case 229: /* fnum: paren fnum ')'  */
#line 449 "grammar.y"
                                { (yyval.f) = (yyvsp[-1].f); }
#line 3528 "y.tab.c"
    break;


#line 3532 "y.tab.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 451 "grammar.y"


int
yyerror(char *msg)
{
   ++argus_n_errors;
   return(1);
}
