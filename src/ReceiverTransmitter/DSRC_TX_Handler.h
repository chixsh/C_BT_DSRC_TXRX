//
// Created by trl on 2/22/16.
//

#include <stdio.h>
#include <ctype.h>
#include <termio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>

#include "wave.h"

/* ASN API's for BSM */
#include <asn_application.h>
#include <asn_internal.h>
#include <BasicSafetyMessage.h>


int Initialize_DSRC_TX_Environment(int arg, char *argv[]);

void *DSRC_TX_Main_Thread(void *arg);
