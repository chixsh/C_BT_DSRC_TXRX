# Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

# Proprietary and Confidential Material.

#TOOLCHAIN=/opt/build/toolchain/PB44/buildroot/build_mips/staging_dir/usr/bin
#CC=mips-linux-uclibc-gcc
include ./makefile_tlcn.inc

export PATH:=$(TOOLCHAIN):/${PATH}
OBJDIR= ./../..

INCS+= -I ${OBJDIR}/incs

INCS+= -I ${OBJDIR}/src

BINDIR= ${OBJDIR}/bin

LIBDIR= ${OBJDIR}/lib


ALL= BT_DSRC_RX


all:	${ALL}
	mv -f ${ALL} ${OBJDIR}/bin

%.o: %.c
	$(CC) $(INCS) -c -DLOCOMATE -DSDK_NEW -o $@ $<

LDFLAGS= -lm -lpthread -lwave -lbluetooth -L $(LIBDIR) -Xlinker -rpath -Xlinker $(LIBDIR) -lwave-encdec -Lasn1c/

BT_DSRC_RX: BT_DSRC_RX.o BT_LIB_RX.o DSRC_LIB_RX.o BT_ASD.o
	${CC} -g  ${LDFLAGS} -o BT_DSRC_RX BT_DSRC_RX.o BT_LIB_RX.o DSRC_LIB_RX.o  BT_ASD.o

clean:
	rm -f *.o
	cd ${BINDIR}; rm -f BT_DSRC_RX; cd -
