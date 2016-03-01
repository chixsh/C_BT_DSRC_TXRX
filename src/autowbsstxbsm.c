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

/* ASN API's for BSM */
#include <asn_application.h>
#include <asn_internal.h>
#include <BasicSafetyMessage.h>

#define PKT_DELAY_SECS 0
#define PKT_DELAY_NSECS 100000000

/* Declarations of WME Data Structures. 
 * These data structures shall be used by the applications to exchange data with the WME and
 * therefore, each application should maintain their local copies of the relevant structs.
 */
//static PSTEntry entry;
static WMEApplicationRequest wreq;
static WMEApplicationRequest entry;
static WMETARequest tareq;
static WSMRequest wsmreq;
//static WMECancelTxRequest cancelReq;
static int pid;

extern void mysleep(int sleep_secs, long int sleep_nsecs);

/* Callback function declarations */
void receiveWME_NotifIndication(WMENotificationIndication *wmeindication);

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication);

void receiveTsfTimerIndication(TSFTimer *timer);
//int	 confirmBeforeJoin(u_int8_t acid, ACM acm);  This is for user only

/* Function Declarations */
int buildPSTEntry();

int buildWSMRequestPacket();

int buildWMEApplicationRequest();

int buildWMETARequest();

int txWSMPPkts(int);

/* Signal Handling functions */
void sig_int(void);

void sig_term(void);

static uint64_t packets;
static uint64_t drops = 0;

struct ta_argument {
    uint8_t channel;
    uint8_t channelinterval;
} taarg;

int main(int argc, char *argv[]) {
    int result;
    pid = getpid();
    /* Checking the user input, if it is less than 4 print the usage message */
    if (argc < 4) {
        printf("usage: cmd [sch channel access <1 - alternating> <0 - continous>] [TA channel ] [ TA channel interval <1- cch int> <2- sch int>] \n");
        return 0;
    }
    taarg.channel = atoi(argv[2]);
    taarg.channelinterval = atoi(argv[3]);
    printf("Filling Provider Service Table entry %d\n", buildPSTEntry(argv));
    printf("Building a WSM Request Packet %d\n", buildWSMRequestPacket());
    printf("Building a WME Application  Request %d\n", buildWMEApplicationRequest());
    printf("Builing TA request %d\n", buildWMETARequest());

    /* Function invokeWAVEDevice(int type, int blockflag)/invokeWAVEDriver(int blockflag) instructs the libwave 
     * to open a connection to a wave device either on the local machine or on a remote machine. 
     * Invoke the wave device before issuing any request to the wave device.
     * If you going to run your application on Local Device(RSU/OBU) you should call invokeWAVEDriver(int blockflag). 
     * If you going to run your application on Remote machine(Computer/laptop,etc),
     * you should call invokeWAVEDevice(int type, int blockflag).
     * For type = WAVEDEVICE_REMOTE, before calling invokeWAVEDevice(int type, int blockflag) make a call to API Details 
     * int setRemoteDeviceIP(char *ipaddr) to set the IP address of the remote wave device 
     */
    if (invokeWAVEDriver(0) < 0) {
        printf("Opening Failed.\n ");
        exit(-1);
    } else {
        printf("Driver invoked\n");
    }
    /* Registering the call back functions */
    registerWMENotifIndication(
            receiveWME_NotifIndication); /* It is called when WME Notification received by application */
    registerWRSSIndication(receiveWRSS_Indication);    /* It is WRSS indication */
    registertsfIndication(receiveTsfTimerIndication);    /* Used to Indicate the Timing Synchronus Function */

    /* Registering the application. You can register the application as a provider/user. 
     * Provider can transmit WSA(WBSS) packets. but user cant.
     * In order to initiate communications on a SCH, an RSU or an OBU transmits WAVE Announcement action frames on the CCH 
     * to advertise offered services available on that SCH such a device is the initiator of a WBSS called a provider. 
     * An OBU receives the announcement on the CCH and generally establishes communications with the provider on the specified SCH, 
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

    /* Timing Advertisement used to provide timing information to user, like channel, channel switching interval, 
     * repeate rate, action and service priority
     */
    printf("starting TA\n");
    if (transmitTA(&tareq) < 0) {
        printf("send TA failed\n ");
    } else {
        printf("send TA successful\n");
    }
    /*if ( startWBSS ( pid, &wreq) < 0) {
      printf("\n WBSS start failed  " );
      exit (-1);
      } else {
      printf("\nWBSS started");
      }*/

    /* Call the Transmit function to Tx WSMP packets */
    result = txWSMPPkts(pid);
    if (result == 0)
        printf("All Packets transmitted\n");
    else
        printf("%d Packets dropped\n", result);

    return 1;
}

/* Function to build the Provider Service Table Entry */
int buildPSTEntry(char **argv) {
    entry.psid = 10;
    entry.priority = 1;
    entry.channel = 172;
    entry.repeatrate = 50; /* repeatrate =50 per 5seconds = 1Hz */
    if (atoi(argv[1]) > 1) {
        printf("channel access set default to alternating access\n");
        entry.channelaccess = CHACCESS_ALTERNATIVE;
    } else {
        entry.channelaccess = atoi(argv[1]);
    }

    return 1;
}

/* Function to build the WSM Request packet.
 * Main use of this function is we will encapsulate the BSM related info in to WSM request packet
 */
int buildWSMRequestPacket() {
    int j;
    static int count = 0;
    asn_enc_rval_t rvalenc;

    count++;                   /* count for the Number of packets Tx */
    /* WSM Channel and Tx info */
    wsmreq.chaninfo.channel = 172;
    wsmreq.chaninfo.rate = 3;
    wsmreq.chaninfo.txpower = 15;
    wsmreq.version = 1;
    wsmreq.security = 1;
    wsmreq.psid = 10;
    wsmreq.txpriority = 1;
    memset(&wsmreq.data, 0, sizeof(WSMData));
    /* BSM related information */
    BasicSafetyMessage_t *bsm; /* BSM Data structure declaration */
    bsm = (BasicSafetyMessage_t *) calloc(1, sizeof(*bsm));
    bsm->msgID.buf = (uint8_t *) calloc(1, sizeof(uint8_t)); /* allocate memory for buffer which is used to store, 
                                                              * what type of message it is
                                                              */
    /* DSRCmsgID_basicSafetyMessage - BSM
     * DSRCmsgID_probeVehicleData - PVD
     * DSRCmsgID_roadSideAlert - RSA
     * DSRCmsgID_intersectionCollisionAlert 
     * DSRCmsgID_mapData - MAP
     * DSRCmsgID_signalPhaseAndTimingMessage - SPAT
     * DSRCmsgID_travelerInformation - TIM
     * These are the available/supported SAE message format's 
     * For each type you need choose the appropriate structure
     */
    bsm->msgID.size = sizeof(uint8_t);
    bsm->msgID.buf[0] = DSRCmsgID_basicSafetyMessage; /* Choose what type of message you want to transfer */
    bsm->blob1.buf = (uint8_t *) calloc(1, 38 * sizeof(uint8_t)); /* Allocate the memory for the blob buffer,
                                                                 * which is used to store the data
                                                                 */
    bsm->blob1.size = 38 * sizeof(uint8_t);
    for (j = 0; j < 38; j++) {
        bsm->blob1.buf[j] = j; /* We are filling some dummy data because of It is a Sample application */
    }
    bsm->blob1.buf[0] = count % 1000;
    rvalenc = der_encode_to_buffer(&asn_DEF_BasicSafetyMessage, bsm, &wsmreq.data.contents,
                                   1000); /* Encode your BSM in to WSM Packets */
    if (rvalenc.encoded == -1) {
        fprintf(stderr, "Cannot encode %s: %s\n",
                rvalenc.failed_type->name, strerror(errno));
    } else {
        printf("Structure successfully encoded %d\n", rvalenc.encoded);
        wsmreq.data.length = rvalenc.encoded;
        asn_DEF_BasicSafetyMessage.free_struct(&asn_DEF_BasicSafetyMessage, bsm, 0);
    }
    return 1;
}

int buildWMEApplicationRequest() {
    wreq.psid = 10;
    printf(" WME App Req %d \n", wreq.psid);
    //strncpy(wreq.acm.contents, entry.acm.contents, OCTET_MAX_LENGTH);
    //printf(" WME App Req %s \n",wreq.acm.contents);
    //wreq.acm.length = entry.acm.length;
    wreq.repeats = 1;
    wreq.persistence = 1;
    wreq.channel = 172;
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

int txWSMPPkts(int pid) {
    //int pwrvalues, ratecount, txprio, ret = 0, pktcount, count = 0;
    int ret = 0, count = 0;

    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);

    while (1) {
        buildWSMRequestPacket();
        //usleep(2000);
        ret = txWSMPacket(pid, &wsmreq);
        if (ret < 0) {
            drops++;
        }
        else {
            packets++;
            count++;
        }
        printf("Transmitted #%llu#					Dropped #%llu#\n", packets, drops);
        //sched_yield();
        mysleep(PKT_DELAY_SECS, PKT_DELAY_NSECS);
    }
    printf("\n Transmitted =  %d dropped = %llu\n", count, drops);
    //cancelReq.aci = 0;
    //cancelReq.channel = 172;
    //cancelTX ( pid, &cancelReq); 
    return drops;
}

void receiveWME_NotifIndication(WMENotificationIndication *wmeindication) {
}

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication) {
    printf("WRSS recv channel %d", (u_int8_t) wrssindication->wrssreport.channel);
    printf("WRSS recv reportt %d", (u_int8_t) wrssindication->wrssreport.wrss);
}

void receiveTsfTimerIndication(TSFTimer *timer) {
    printf("TSF Timer: Result=%d, Timer=%llu", (u_int8_t) timer->result, (u_int64_t) timer->timer);
}

int confirmBeforeJoin(u_int8_t psid) {
    printf("Link Confirmed PSID=%d\n", (u_int8_t) psid);
    return 0;
}

void sig_int(void) {
    int ret;
    ret = stopWBSS(pid, &wreq);
    removeProvider(pid, &entry);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("Packets Dropped = %llu\n", drops);
    printf("localtx killed by control-C\n");
    exit(0);

}

void sig_term(void) {
    int ret;
    ret = stopWBSS(pid, &wreq);
    removeProvider(pid, &entry);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("\nPackets Dropped = %llu\n", drops);
    printf("localtx killed by control-C\n");
    exit(0);
}
