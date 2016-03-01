/*
 * Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.
 * Proprietary and Confidential Material.
 *
 */

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

/**
 * Declarations of WME Data Structures. 
 * These data structures shall be used by the applications to exchange data with the WME 
 * and therefore, each application should maintain their local copies of the relevant structs 
 */
static WMEApplicationRequest entry;
static WMETARequest tareq;
static WSMRequest wsmreq;

/* Function Declarations */
int buildPSTEntry();

/* Function to fill the Provider Service Table Entry */
int buildWSMRequestPacket();

/* Function to build the WAVE Short Message request Packet */
int buildWMETARequest();

int txWSMPPkts(int); /* Function to Transmit the WSMP packets */
/* Signal Handling Functions */
void sig_int(void);

void sig_term(void);

static uint64_t packets;
static uint64_t drops = 0;
static int pid;
//static char Data[30]="LOCOMATE-ARADA SYSTEMS";
//static char Data[4096];   /* BA- TBD proper fix for 4k wsmp support */
static char Data[1300];
static uint16_t len = 500;
int IPdelay = 2, txpower = 14, datarate = 3, notxpkts = 0;

struct ta_argument {
    uint8_t channel;
    uint8_t channelinterval;
} taarg;

int main(int argc, char *argv[]) {
    int result, i;
    pid = getpid();

    /* checking the input from the user. 
     * if the arguments less than 6 it will display the usage message
     */
    if (argc < 6) {
        printf("usage: localtx [sch channel access <1 - alternating> <0 - continous>] [TA channel ] [ TA channel interval <1- cch int> <2- sch int>] [SCH Channel] [Priority] [pktsize] [IPdelay] [TxPower] [DataRate] [NoTxPkts]\n");
        return 0;
    }
    taarg.channel = atoi(argv[2]);
    taarg.channelinterval = atoi(argv[3]);
    /* Filling the user input to appropriate variables */
    if (argc > 6)
        len = atoi(argv[6]);
    if (argc > 7)
        IPdelay = atoi(argv[7]);
    if (argc > 8)
        txpower = atoi(argv[8]);
    if (argc > 9)
        datarate = atoi(argv[9]);
    if (argc > 10)
        notxpkts = atoi(argv[10]);

    /* Here we are filling the array with dummy data, bcoz it is a sample application for TX. */
    for (i = 0; i <= len; i++)
        Data[i] = 'V';

    printf("Filling Provider Service Table entry %d\n", buildPSTEntry(argv));
    printf("Building a WSM Request Packet %d\n", buildWSMRequestPacket());
    printf("Builing TA request %d\n", buildWMETARequest());

    /* Function invokeWAVEDevice(int type, int blockflag)/invokeWAVEDriver(int blockflag) 
     * instructs the libwave to open a connection to a wave device either on the local machine 
     * or on a remote machine. 
     * Invoke the wave device before issuing any request to the wave device 
     *
     * If you going to run your application on Local Device(RSU/OBU) 
     * you should call invokeWAVEDriver(int blockflag).
     *
     * If you going to run your application on Remote machine(Computer/laptop,etc) 
     * you should call invokeWAVEDevice(int type, int blockflag).
     *
     * For type = WAVEDEVICE_REMOTE, before calling invokeWAVEDevice(int type, int blockflag) 
     * make a call to API Details int setRemoteDeviceIP(char *ipaddr) to set the IP address 
     * of the remote wave device 
     */

    if (invokeWAVEDriver(0) < 0) {
        printf("Opening Failed.\n ");
        exit(-1);
    } else {
        printf("Driver invoked\n");

    }

    /* Registering the application. 
     * You can register the application as a provider/user. 
     * 
     * Provider can transmit WSA(WBSS) packets. but user cant.
     * In order to initiate communications on a SCH, an RSU or an OBU transmits 
     * WAVE Announcement action frames on the CCH to advertise offered services available on 
     * that SCH such a device is the initiator of a WBSS called a provider. 
     * An OBU receives the announcement on the CCH 
     * and generally establishes communications with the provider on the specified SCH, 
     * such a device is called a user.
     */
    printf("Registering provider\n ");
    if (registerProvider(pid, &entry) < 0) {
        printf("\nRegister Provider failed\n");
        removeProvider(pid, &entry);
        registerProvider(pid, &entry);
    } else {
        printf("provider registered with PSID = %u\n", entry.psid);
    }
    printf("starting TA\n");
    if (transmitTA(&tareq) < 0) {
        printf("send TA failed\n ");
    } else {
        printf("send TA successful\n");
    }
    /* Call the Transmit function to Tx WSMP packets */
    result = txWSMPPkts(pid);
    if (result == 0)
        printf("All Packets transmitted\n");
    else
        printf("%d Packets dropped\n", result);
    sig_int();
    return 1;
}


/* Function to fill the PST Entry*/
int buildPSTEntry(char **argv) {
    entry.psid = 5;/* Provider Service IDentifier of the process. 
                      you cant register 2 applications with same psid. */
    entry.priority = atoi(argv[5]);
    entry.channel = atoi(argv[4]);
    entry.repeatrate = 50; /* repeatrate =50 per 5seconds = 1Hz */
    if (atoi(argv[1]) > 1) {
        printf("channel access set default to alternating access\n");
        entry.channelaccess = CHACCESS_ALTERNATIVE;
    } else {
        entry.channelaccess = atoi(argv[1]);
    }

    return 1;
}


/* Function to fill the WSM request packet*/
int buildWSMRequestPacket() {
    wsmreq.chaninfo.channel = entry.channel;
    wsmreq.chaninfo.rate = datarate;
    wsmreq.chaninfo.txpower = txpower;
    wsmreq.version = 1;
    wsmreq.security = 0;
    wsmreq.psid = 5;
    wsmreq.txpriority = 2;
    memset(&wsmreq.data, 0, sizeof(WSMData));
    memcpy(&wsmreq.data.contents, &Data, len);
    memcpy(&wsmreq.data.length, &len, sizeof(len));
    return 1;

}

int buildWMETARequest() {
    tareq.action = TA_ADD;
    tareq.repeatrate = 100;
    tareq.channel = taarg.channel;
    tareq.channelinterval = taarg.channelinterval;
    tareq.servicepriority = 1;
    return 0;
}

/* Function to Tx WSMP Packets */
int txWSMPPkts(int pid) {
    int ret = 0, count = 0;
    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);

    while (1) {
        ret = txWSMPacket(pid, &wsmreq);
        if (ret < 0) {
            drops++;
        }
        else {
            packets++;
            count++;
        }
        if ((notxpkts != 0) && (count >= notxpkts))
            break;
        printf("Transmitted #%llu#					Dropped #%llu# len #%u#\n", packets, drops, wsmreq.data.length);
        //usleep(2000);
        usleep(IPdelay * 1000);
    }
    printf("\n Transmitted =  %d dropped = %llu\n", count, drops);
    return drops;
}

/* Signal handling functions */
/* Before killing/Termination your application, 
 * make sure you unregister the application.
 */
void sig_int(void) {

    removeProvider(pid, &entry);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("Packets Dropped = %llu\n", drops);
    printf("localtx killed by control-C\n");
    exit(0);

}

void sig_term(void) {

    removeProvider(pid, &entry);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("\nPackets Dropped = %llu\n", drops);
    printf("localtx killed by control-C\n");
    exit(0);
}
