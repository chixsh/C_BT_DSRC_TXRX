# Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

# Proprietary and Confidential Material.

#TOOLCHAIN=/opt/build/toolchain/PB44/buildroot/build_mips/staging_dir/usr/bin
#CC=mips-linux-uclibc-gcc
include ./makefile_tlcn.inc

export PATH:=$(TOOLCHAIN):/${PATH}
OBJDIR= ./..
INCS+= -I ${OBJDIR}/incs
#INCS+= -I ${OBJDIR}/socket-CAN/include

INCS+= -I ${OBJDIR}/src

BINDIR= ${OBJDIR}/bin

LIBDIR= ${OBJDIR}/lib


ALL= wsmpdemo localtx localtx_sec localrx localrx_sec bluetoothrx bluetoothtx localrxbsm localtxbsm


all:	${ALL}
	mv -f ${ALL} ${OBJDIR}/bin

%.o: %.c
	$(CC) $(INCS) -c -DLOCOMATE -DSDK_NEW -o $@ $<

LDFLAGS= -lm -lpthread -lwave -lbluetooth -L $(LIBDIR) -Xlinker -rpath -Xlinker $(LIBDIR) -lwave-encdec -Lasn1c/


wsmpdemo: wsmpdemo.o  wavelogger.o wavegps.o gpsc_probe.o asnlogger.o
	${CC} -g   $(LDFLAGS) -o wsmpdemo  wsmpdemo.o  wavelogger.o wavegps.o gpsc_probe.o asnlogger.o

localtx: autowbsstx.o
	${CC} -g  ${LDFLAGS} -o localtx autowbsstx.o

localtxbsm: autowbsstxbsm.o
	${CC} -g  ${LDFLAGS} -o localtxbsm autowbsstxbsm.o

localrx: autowbssrx.o
	${CC} ${LDFLAGS} -o localrx autowbssrx.o wavegps.o gpsc_probe.o

localrxbsm: autowbssrxbsm.o
	${CC} ${LDFLAGS} -o localrxbsm autowbssrxbsm.o wavegps.o gpsc_probe.o

localtx_sec: autowbsstxsec.o UserApi.o msg.o
	${CC} -g  ${LDFLAGS} -o localtx_sec autowbsstxsec.o UserApi.o msg.o

localrx_sec: autowbssrxsec.o UserApi.o msg.o
	${CC} -g   ${LDFLAGS} -o localrx_sec autowbssrxsec.o UserApi.o msg.o

bluetoothtx: bluetoothtx.o
	${CC} -g  ${LDFLAGS} -o bluetoothtx  bluetoothtx.o

bluetoothrx: bluetoothrx.o bluetooth_asd.o
	${CC} -g  ${LDFLAGS} -o bluetoothrx  bluetoothrx.o bluetooth_asd.o

clean:
	rm -f *.o
	cd ${BINDIR}; rm -f bluetoothrx bluetoothtx localrx_sec localtx_sec localrxbsm localtxbsm localrx localtx wsmpdemo; cd -
