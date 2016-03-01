/*

 * Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

 * Proprietary and Confidential Material.

 *

 */

#include <stdio.h>
#include <ctype.h>
#include <termio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>
#include "wave.h"
#include "tool_def.h"
#include "AsmDef.h"
#include "genericAPI.h"

// User with ACID = 1 and ACM = demo
void sig_int(void);

void sig_term(void);

static int pid;
//static USTEntry entry;
static WMEApplicationRequest entry;
static uint64_t count = 0, blank = 0;

int confirmBeforeJoin(WMEApplicationIndication *);

void set_args(void *, void *, int);

enum {
    ADDR_MAC = 0, UINT8_T
};
struct arguments {
    u_int8_t macaddr[17];
    u_int8_t channel;
};
UINT8 send_buff[10240];
UINT8 recv_buff[10240];
int socket_id;
static struct timeval tvstart, tvend;

int AsmVerifyData(WSMIndication *rxpkt) {
    int send_size = 0, recv_size = 0, size1 = 0;
    int idx = 0, retIdx = 0;
    uint32_t psid = 0;
    // send AsmMsg_Verify request
    bzero(send_buff, sizeof(send_buff));
    msg_create_verify_msg(rxpkt->data.contents, send_buff, &send_size, 0, 0, 0, 0, 0);
    INFO("Send AsmMsg_Verify request. [0x%02x]", send_buff[0]);
    if (0 != AsmSend(send_buff, send_size, socket_id)) {
        return -1;
    }
    // receive AsmMsg_Verify response
    bzero(recv_buff, sizeof(recv_buff));
    recv_size = AsmRecv(recv_buff, sizeof(recv_buff), socket_id);
    if (recv_size <= 0) {
        return -1;
    }
    if (recv_buff[0] != CMD_OK_VERIFY_POST) {
        ERROR("Receive error. [0x%02x]", recv_buff[0]);
        return -1;
    } else {
        INFO("Receive AsmMsg_Verify response. [0x%02x]", recv_buff[0]);
    }

    psid = getPsidbyLen(&recv_buff[10], &retIdx);
    INFO("Receive AsmMsg_Verify PSID:%d", psid);
    idx = 10 + retIdx;
    retIdx = 0;
    send_size = 0;
    send_size = getValbyLen(&recv_buff[idx], &retIdx);
    idx = idx + retIdx;
    memcpy(rxpkt->data.contents, &recv_buff[idx], send_size);
    rxpkt->data.length = send_size;
    return 0;
}

int AsmDecryptData(WSMIndication *rxpkt) {
    int send_size = 0, recv_size = 0;
    // send AsmMsg_Dec request
    bzero(send_buff, sizeof(send_buff));
    msg_create_dec_msg(rxpkt->data.contents, send_buff, &send_size);
    INFO("Send AsmMsg_Dec request. [0x%02x]", send_buff[0]);
    if (0 != AsmSend(send_buff, send_size, socket_id)) {
        return -1;
    }
    // receive AsmMsg_Dec response
    bzero(recv_buff, sizeof(recv_buff));
    recv_size = AsmRecv(recv_buff, sizeof(recv_buff), socket_id);
    if (recv_size <= 0) {
        return -1;
    }
    if (recv_buff[0] != CMD_OK_DEC_POST) {
        ERROR("Receive error. [0x%02x]", recv_buff[0]);
        return -1;
    } else {
        INFO("Receive AsmMsg_Dec response. [0x%02x]", recv_buff[0]);
    }
    bzero(send_buff, sizeof(send_buff));
    msg_decode_dec_msg(send_buff, recv_buff, &recv_size);
    memcpy(rxpkt->data.contents, &send_buff, recv_size);
    rxpkt->data.length = recv_size;
    return 0;
}

int main(int arg, char *argv[]) {

    WSMIndication rxpkt;
    //int i, attempts = 10, drops = 0, result;
    int ret = 0;
    struct arguments arg1;
    int security;

    if (arg < 4) {
        printf("usage: localrx [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [channel <optional>] [PROVIDER MAC <optional>] [Security <0: No Security> <1: Sign/verify> <2: Enc/Dec>] \n");
        return 0;
    }
    registerLinkConfirm(confirmBeforeJoin);
    pid = getpid();
    memset(&entry, 0, sizeof(WMEApplicationRequest));
    entry.psid = 20;
    if ((atoi(argv[1]) > USER_REQ_SCH_ACCESS_NONE) || (atoi(argv[1]) < USER_REQ_SCH_ACCESS_AUTO)) {
        printf("User request type invalid: setting default to auto\n");
        entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;

    } else {
        entry.userreqtype = atoi(argv[1]);
    }
    if (entry.userreqtype == USER_REQ_SCH_ACCESS_AUTO_UNCONDITIONAL) {
        if (arg < 5) {
            printf("channel needed for unconditional access\n");
            return 0;
        } else {
            entry.channel = atoi(argv[4]);
        }
    }

    entry.schaccess = atoi(argv[2]);
    entry.schextaccess = atoi(argv[3]);
    security = atoi(argv[5]);
    if (arg > 5) {
        strncpy(arg1.macaddr, argv[4], 17);
        set_args(entry.macaddr, &arg1, ADDR_MAC);
    }
    printf("Invoking WAVE driver \n");

    if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
        printf("Open Failed. Quitting\n");
        exit(-1);
    }

    printf("Registering User %d\n", entry.psid);
    if (registerUser(pid, &entry) < 0) {
        printf("Register User Failed \n");
        printf("Removing user if already present  %d\n", !removeUser(pid, &entry));
        printf("USER Registered %d with PSID =%u \n", registerUser(pid, &entry), entry.psid);
    }


    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);
    socket_id = AsmConnect(TX_SOCKET, DEFAULT_DEV_ADDR);
    while (1) {
        ret = rxWSMPacket(pid, &rxpkt);
        if (count == 0)
            gettimeofday(&tvstart, NULL);
        if (ret > 0) {
            printf("Received WSMP Packet txpower= %d, rateindex=%d Packet No =#%llu#\n", rxpkt.chaninfo.txpower,
                   rxpkt.chaninfo.rate, count++);
            if (security == 1)
                AsmVerifyData(&rxpkt);
            else if (security == 2) {
                AsmDecryptData(&rxpkt);
            }
        } else {
            blank++;
        }

    }

}

void sig_int(void) {
//	int ret;
    unsigned long timedif_usec;
    unsigned int latency;

    removeUser(pid, &entry);
    AsmDisconnect(socket_id, 0);
    gettimeofday(&tvend, NULL);
    timedif_usec = (((tvend.tv_sec * 1000000) + tvend.tv_usec) - ((tvstart.tv_sec * 1000000) + tvstart.tv_usec));
    if (count) {
        latency = timedif_usec / count;
        printf(" Latency (usec)  %d\n", latency);
    } else
        printf(" NO Packets Received\n");
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);

}

void sig_term(void) {
//	int ret;
    unsigned long timedif_usec;
    unsigned int latency;

    removeUser(pid, &entry);
    AsmDisconnect(socket_id, 0);
    gettimeofday(&tvend, NULL);
    timedif_usec = (((tvend.tv_sec * 1000000) + tvend.tv_usec) - ((tvstart.tv_sec * 1000000) + tvstart.tv_usec));
    latency = timedif_usec / count;
    printf(" latency in microsec %d\n", latency);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);
}

int confirmBeforeJoin(WMEApplicationIndication *appind) {
    printf("\nJoin\n");
    return 1; /*Return 0 for NOT Joining the WBSS*/
}


int extract_macaddr(u_int8_t *mac, char *str) {
    int maclen = IEEE80211_ADDR_LEN;
    int len = strlen(str);
    int i = 0, j = 0, octet = 0, digits = 0, ld = 0, rd = 0;
    char num[2];
    u_int8_t tempmac[maclen];
    memset(tempmac, 0, maclen);
    memset(mac, 0, maclen);
    if ((len < (2 * maclen - 1)) || (len > (3 * maclen - 1)))
        return -1;
    while (i < len) {
        j = i;
        while (str[i] != ':' && (i < len)) {
            i++;
        }
        if (i > len) exit(0);
        digits = i - j;
        if ((digits > 2) || (digits < 1) || (octet >= maclen)) {
            return -1;
        }
        num[1] = tolower(str[i - 1]);
        num[0] = (digits == 2) ? tolower(str[i - 2]) : '0';
        if (isxdigit(num[0]) && isxdigit(num[1])) {
            ld = (isalpha(num[0])) ? 10 + num[0] - 'a' : num[0] - '0';
            rd = (isalpha(num[1])) ? 10 + num[1] - 'a' : num[1] - '0';
            tempmac[octet++] = ld * 16 + rd;
        } else {
            return -1;
        }
        i++;
    }
    if (octet > maclen)
        return -1;
    memcpy(mac, tempmac, maclen);
    return 0;
}


void set_args(void *data, void *argname, int datatype) {
    u_int8_t string[1000];
//    int i;
//    int temp = 0;
//    u_int8_t temp8 = 0; 
    struct arguments *argument1;
    argument1 = (struct arguments *) argname;
    switch (datatype) {
        case ADDR_MAC:
            memcpy(string, argument1->macaddr, 17);
            string[17] = '\0';
            if (extract_macaddr(data, string) < 0) {
                printf("invalid address\n");
            }
            break;
        case UINT8_T:

            //temp = atoi(argument1->channel);
            memcpy(data, (char *) argname, sizeof(u_int8_t));
            break;
    }
}


