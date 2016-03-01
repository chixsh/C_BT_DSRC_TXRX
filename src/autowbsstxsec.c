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
#include "tool_def.h"
#include "AsmDef.h"
#include "genericAPI.h"

//static PSTEntry entry;
static WMEApplicationRequest wreq;
static WMEApplicationRequest entry;
static WMETARequest tareq;
static WSMRequest wsmreq;
//static WMECancelTxRequest cancelReq;
static int pid;
static struct timeval tvstart, tvend;

void receiveWME_NotifIndication(WMENotificationIndication *wmeindication);

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication);

void receiveTsfTimerIndication(TSFTimer *timer);
//int	 confirmBeforeJoin(u_int8_t acid, ACM acm);  This is for user only


#define DEFAULT_SERVICE_CHANNEL 172

int buildPSTEntry(char **);

int buildWSMRequestPacket(char **);

int buildWMEApplicationRequest(char **);

int buildWMETARequest();

int txWSMPPkts(int);

void sig_int(void);

void sig_term(void);

static uint64_t packets = 0;
static uint64_t drops = 0;
UINT8 send_buff[10240];
UINT8 recv_buff[10240];
int socket_id;
int service_chan = 172;

struct ta_argument {
    uint8_t channel;
    uint8_t channelinterval;
} taarg;

int main(int argc, char *argv[]) {
    int result;
    pid = getpid();

    if (argc < 7) {
        printf("usage: localtx_sec [sch channel access <1 - alternating> <0 - continous>] [TA channel ] [ TA channel interval <1- cch int> <2- sch int>] [Security <0: No Security> <1: Sign/verify> <2: Enc/Dec>] [Service Channel] [priority]\n");
        return 0;
    }
    taarg.channel = atoi(argv[2]);
    taarg.channelinterval = atoi(argv[3]);
    printf("Filling Provider Service Table entry %d\n", buildPSTEntry(argv));
    printf("Building a WSM Request Packet %d\n", buildWSMRequestPacket(argv));
    printf("Building a WME Application  Request %d\n", buildWMEApplicationRequest(argv));
    printf("Builing TA request %d\n", buildWMETARequest());

    if (invokeWAVEDriver(0) < 0) {
        printf("Opening Failed.\n ");
        exit(-1);
    } else {
        printf("Driver invoked\n");

    }

    registerWMENotifIndication(receiveWME_NotifIndication);
    registerWRSSIndication(receiveWRSS_Indication);
    registertsfIndication(receiveTsfTimerIndication);

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
    /*if ( startWBSS ( pid, &wreq) < 0) {
        printf("\n WBSS start failed  " );
        exit (-1);
    } else {
        printf("\nWBSS started");
    }*/

    result = txWSMPPkts(pid);
    if (result == 0)
        printf("All Packets transmitted\n");
    else
        printf("%d Packets dropped\n", result);

    return 1;


}


int buildPSTEntry(char **argv) {

    entry.psid = 20;
    entry.priority = atoi(argv[6]);
    if (atoi(argv[5]))
        entry.channel = atoi(argv[5]);
    else
        entry.channel = DEFAULT_SERVICE_CHANNEL;
    entry.repeatrate = 50; // repeatrate =50 per 5seconds = 1Hz
    if (atoi(argv[1]) > 1) {
        printf("channel access set default to alternating access\n");
        entry.channelaccess = CHACCESS_ALTERNATIVE;
    } else {
        entry.channelaccess = atoi(argv[1]);
    }

    return 1;
}


int buildWSMRequestPacket(char **argv) {
    if (atoi(argv[5]))
        wsmreq.chaninfo.channel = atoi(argv[5]);
    else
        wsmreq.chaninfo.channel = DEFAULT_SERVICE_CHANNEL;
    wsmreq.chaninfo.rate = 3;
    wsmreq.chaninfo.txpower = 15;
    wsmreq.version = 1;
    if (atoi(argv[4]))
        wsmreq.security = atoi(argv[4]);
    wsmreq.psid = 20;
    wsmreq.txpriority = atoi(argv[6]);
    memset(&wsmreq.data, 0, sizeof(WSMData));
    memcpy(&wsmreq.data.contents, "assadsad", 9);
    wsmreq.data.length = 9;
    return 1;

}

int buildWMEApplicationRequest(char **argv) {
    wreq.psid = 20;
    printf(" WME App Req %d \n", wreq.psid);
    //strncpy(wreq.acm.contents, entry.acm.contents, OCTET_MAX_LENGTH);
    //printf(" WME App Req %s \n",wreq.acm.contents);
    //wreq.acm.length = entry.acm.length;
    wreq.repeats = 1;

    wreq.persistence = 1;
    if (atoi(argv[5]))
        wreq.channel = atoi(argv[5]);
    else
        wreq.channel = DEFAULT_SERVICE_CHANNEL;
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

int AsmSignData() {
    int send_size = 0, recv_size = 0;//,i;
    uint32_t psId = 0, psidLen = 0;
    // send AsmMsg_Sign request
    if (BIGENDIAN)
        psId = swap32_(entry.psid);
    psId = putPsidbyLen(&psId, entry.psid, &psidLen);
    msg_create_sign_msg(send_buff, wsmreq.data.contents, &send_size, wsmreq.data.length, 0, &psId, psidLen, 0, 0, 0);
    INFO("Send AsmMsg_Sign request. [0x%02x]", send_buff[0]);

    if (0 != AsmSend(send_buff, send_size, socket_id)) {
        ERROR(" Sending error.\n");
        return -1;
    }

    // receive AsmMsg_Sign response
    bzero(recv_buff, sizeof(recv_buff));
    recv_size = AsmRecv(recv_buff, sizeof(recv_buff), socket_id);
    if (recv_size <= 0) {
        return -1;
    }
    if (recv_buff[0] != CMD_OK_SIGN_POST) {
        ERROR("Receive error. [0x%02x]", recv_buff[0]);
        return -1;
    }
    else {
        INFO("Receive AsmMsg_Sign response. [0x%02x]", recv_buff[0]);
    }
    memcpy(&wsmreq.data.contents, &recv_buff, recv_size);
    wsmreq.data.length = recv_size;
    return 0;
}

int AsmEncryptData() {
    int send_size = 0, recv_size = 0;//,i;
    // send AsmMsg_Enc request
    bzero(send_buff, sizeof(send_buff));
    msg_create_enc_msg(send_buff, wsmreq.data.contents, &send_size, wsmreq.data.length);
    INFO("Send AsmMsg_Enc request. [0x%02x]", send_buff[0]);
    if (0 != AsmSend(send_buff, send_size, socket_id)) {
        return -1;
    }
    // receive AsmMsg_Enc response
    bzero(recv_buff, sizeof(recv_buff));
    recv_size = AsmRecv(recv_buff, sizeof(recv_buff), socket_id);
    if (recv_size <= 0) {
        return -1;
    }
    if (recv_buff[0] != CMD_OK_ENC_POST) {
        ERROR("Receive error. [0x%02x]", recv_buff[0]);
        return -1;
    }
    else {
        INFO("Receive AsmMsg_Enc response. [0x%02x]", recv_buff[0]);
    }
    memcpy(&wsmreq.data.contents, &recv_buff, recv_size);
    wsmreq.data.length = recv_size;
    return 0;
}

int txWSMPPkts(int pid) {
//	int pwrvalues, ratecount, txprio, ret = 0, pktcount, count = 0;
    int ret = 0, count = 0;

    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);
    socket_id = AsmConnect(TX_SOCKET, DEFAULT_DEV_ADDR);
    gettimeofday(&tvstart, NULL);
    while (1) {
        usleep(2000);
        if (wsmreq.security) {
            memset(&wsmreq.data, 0, sizeof(WSMData));
            memcpy(&wsmreq.data.contents, "assadsad", 9);
            wsmreq.data.length = 9;
            if (wsmreq.security == 1)
                AsmSignData();
            else if (wsmreq.security == 2) {
                AsmEncryptData();
            }
        }
        ret = txWSMPacket(pid, &wsmreq);
        if (ret < 0) {
            drops++;
        }
        else {
            packets++;
            count++;
        }
        printf("Transmitted #%llu#					Dropped #%llu#\n", packets, drops);
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
//	int ret;
    unsigned long timedif_usec;
    unsigned int latency;

    //ret = stopWBSS(pid, &wreq);
    removeProvider(pid, &entry);
    AsmDisconnect(socket_id, 0);
    gettimeofday(&tvend, NULL);
    timedif_usec = (((tvend.tv_sec * 1000000) + tvend.tv_usec) - ((tvstart.tv_sec * 1000000) + tvstart.tv_usec));
    if (packets) {
        latency = timedif_usec / packets;
        printf(" Latency (usec)  %d\n", latency);
    } else
        printf(" NO Packets Transmitted\n");
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("Packets Dropped = %llu\n", drops);
    printf("localtx killed by control-C\n");
    exit(0);

}

void sig_term(void) {
//	int ret;
    unsigned long timedif_usec;
    unsigned int latency;

    //ret = stopWBSS(pid, &wreq);
    removeProvider(pid, &entry);
    AsmDisconnect(socket_id, 0);
    gettimeofday(&tvend, NULL);
    timedif_usec = (((tvend.tv_sec * 1000000) + tvend.tv_usec) - ((tvstart.tv_sec * 1000000) + tvstart.tv_usec));
    if (packets) {
        latency = timedif_usec / packets;
        printf(" Latency (usec)  %d\n", latency);
    } else
        printf(" NO Packets Transmitted\n");
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("\nPackets Dropped = %llu\n", drops);
    printf("localtx killed by control-C\n");
    exit(0);
}

	
