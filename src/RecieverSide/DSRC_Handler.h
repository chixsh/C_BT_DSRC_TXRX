//
// Created by trl on 2/22/16.
//
#include <stdio.h>
#include <ctype.h>
#include <termio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>
#include <asnwave.h>
#include "wave.h"
#include <asnwave.h>


static WMEApplicationRequest DSRC_Entry;


void DSRC_Signal_Interrupt(void);

void DSRC_Signal_Terminate(void);

int DSRC_ConfirmBeforeJoin(WMEApplicationIndication *appind);

void DSRC_Set_Arguments(void *data, void *argname, int datatype);

int Extract_MAC_Address(u_int8_t *mac, char *str);

int Initialize_DSRC_Environment(int arg, char *argv[]);
