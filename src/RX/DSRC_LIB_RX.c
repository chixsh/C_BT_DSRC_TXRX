//
// Created by TRL on 2/12/2016.
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


// User with ACID = 1 and ACM = demo
void sig_int(void);

void sig_term(void);

static int pid;
//static USTEntry entry;
static WMEApplicationRequest entry;
static uint64_t count = 0, blank = 0;


enum {
    ADDR_MAC = 0, UINT8
};

struct arguments {
    u_int8_t macaddr[17];
    u_int8_t channel;
};


void DSRC_Signal_Interrupt(void) {
    removeUser(pid, &entry);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);
}

void DSRC_Signal_Terminate(void) {
    DSRC_Signal_Interrupt();
}


int DSRC_ConfirmBeforeJoin(WMEApplicationIndication *appind) {
    printf("\nJoin\n");
    return 1; /* Return 0 for NOT Joining the WBSS */
}


void DSRC_Set_Arguments(void *data, void *argname, int datatype) {
    u_int8_t string[1000];
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
        case UINT8:

            //temp = atoi(argument1->channel);
            memcpy(data, (char *) argname, sizeof(u_int8_t));
            break;
    }
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


int main__(int arg, char *argv[]) {
    WSMMessage rxmsg;
    WSMIndication rxpkt;
    //int i, attempts = 10, drops = 0, result;
    int ret = 0;
    struct arguments arg1;
    rxmsg.wsmIndication = &rxpkt;

    /* check for the user input arguments, if it is less than 4 print the usage message */
    if (arg < 4) {
        printf("usage: localrxbsm [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [channel <optional>] [PROVIDER MAC <optional>]\n");
        return 0;
    }
    registerLinkConfirm(DSRC_ConfirmBeforeJoin); /* Registering the callback function */
    pid = getpid();
    memset(&entry, 0, sizeof(WMEApplicationRequest));
    entry.psid = 10;
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
    if (arg > 5) {
        strncpy(arg1.macaddr, argv[4], 17);
        DSRC_Set_Arguments(entry.macaddr, &arg1, ADDR_MAC);
    }

    /* Function invokeWAVEDevice(int type, int blockflag)/invokeWAVEDriver(int blockflag) instructs the libwave
     * to open a connection to a wave device either on the local machine or on a remote machine.
     * Invoke the wave device before issuing any request to the wave device
     */
    printf("Invoking WAVE driver \n");
    if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
        printf("Open Failed. Quitting\n");
        exit(-1);
    }

    /* Registering the user to receive the data from the TX application */
    printf("Registering User %d\n", entry.psid);
    if (registerUser(pid, &entry) < 0) {
        printf("Register User Failed \n");
        printf("Removing user if already present  %d\n", !removeUser(pid, &entry));
        printf("USER Registered %d with PSID =%u \n", registerUser(pid, &entry), entry.psid);
    }

    /* catch control-c and kill signal */
    signal(SIGINT, (void *) DSRC_Signal_Interrupt);
    signal(SIGTERM, (void *) DSRC_Signal_Terminate);

    while (1) {
        ret = rxWSMMessage(pid, &rxmsg); /* Function to receive the Data from TX application */
        if (ret > 0) {
            printf("Received WSMP Packet txpower= %d, rateindex=%d Packet No =#%llu#\n", rxpkt.chaninfo.txpower,
                   rxpkt.chaninfo.rate, count++);
            rxWSMIdentity(&rxmsg, 0); //Identify the type of received Wave Short Message.
            if (!rxmsg.decode_status) {
                xml_print(rxmsg); /* call the parsing function to extract the contents of the received message */
            }
        } else {
            blank++;
        }
    }
}



























