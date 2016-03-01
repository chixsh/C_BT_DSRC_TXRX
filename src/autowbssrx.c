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
#include <semaphore.h>
#include "wave.h"

void sig_int(void);

void sig_term(void);

void set_args(void *, void *, int);

/* Callback function declarations */
/* Callback function to Confirm, Before joining with the Tx application */
int user_confirmBeforeJoin(struct wmeNotif_Indication *);

int ReceiveTA_Indication(struct WmeTAIndication *);

static WMEApplicationRequest entry;
struct wmeNotif_Indication notif_done;
struct WmeTAIndication ta_receive;
struct availserviceInfo get_astinfo;

sem_t indication_sem;
static uint64_t count = 0, blank = 0;
static int pid;

enum {
    ADDR_MAC = 0, UINT8
};
struct arguments {
    u_int8_t macaddr[17];
    u_int8_t channel;
};

int main(int arg, char *argv[]) {
    WSMIndication rxpkt;
    int ret = 0;
    struct arguments arg1;
    sem_init(&indication_sem, 0, 0);

    /* Check for user input. If the arguments are less than 4 print the usage message */
    if (arg < 4) {
        printf("usage: localrx [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [channel <optional>] [PROVIDER MAC <optional>]\n");
        return 0;
    }
    pid = getpid();
    memset(&entry, 0, sizeof(WMEApplicationRequest));
    entry.psid = 5;
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
        set_args(entry.macaddr, &arg1, ADDR_MAC);
    }

    /* If the user request type is equal to 3(service channel access none) 
     * call the registered callback function.
     */
    if (entry.userreqtype == USER_REQ_SCH_ACCESS_NONE)
        user_registerLinkConfirm(user_confirmBeforeJoin);

    registerTAIndication(ReceiveTA_Indication);


    printf("Invoking WAVE driver \n");

    /* Function invokeWAVEDevice(int type, int blockflag)/invokeWAVEDriver(int blockflag) 
     * instructs the libwave to open a connection to a wave device either on the local machine 
     * or on a remote machine. 
     * Invoke the wave device before issuing any request to the wave device 
     */
    if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
        printf("Open Failed. Quitting\n");
        exit(-1);
    }

    /* User, An OBU receives the announcement on the CCH 
     * and generally establishes communications with the provider on the specified SCH.
     */
    printf("Registering User %d\n", entry.psid);
    if (registerUser(pid, &entry) < 0) {
        printf("Register User Failed \n");
        printf("Removing user if already present  %d\n", !removeUser(pid, &entry));
        printf("USER Registered %d with PSID =%u \n", registerUser(pid, &entry), entry.psid);
    }

    if (entry.userreqtype == USER_REQ_SCH_ACCESS_NONE) {
        sem_wait(&indication_sem);

        /* Get the available service information based on PSID */
        ret = Get_Available_Serviceinfo(pid, &get_astinfo, entry.psid);
        if (get_astinfo.psid == entry.psid) {
            entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
            ret = registerUser(pid, &entry);
        }

    }


    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);

    while (1) {
        /* Function that will  receive wsmp packets. */
        ret = rxWSMPacket(pid, &rxpkt);
        if (ret > 0) {
            printf("Received WSMP Packet RSSI=%d txpower= %d, rateindex=%d, len=%u, Packet No =#%llu#\n", rxpkt.rssi,
                   rxpkt.chaninfo.txpower, rxpkt.chaninfo.rate, rxpkt.data.length, count++);
        } else {
            blank++;
        }

    }

}

int user_confirmBeforeJoin(struct wmeNotif_Indication *received) {
    memcpy(&notif_done, received, sizeof(struct wmeNotif_Indication));
    sem_post(&indication_sem);
    return 1;
}

int ReceiveTA_Indication(struct WmeTAIndication *received) {
    uint64_t tsftimer;
    memcpy(&ta_receive, received, sizeof(struct WmeTAIndication));
    memcpy(&tsftimer, ta_receive.ta_info.timevalue, sizeof(uint64_t));
    /* Received timevalue is in nano seconds so we need to convert to micro seconds,
     * and 2 milliseconds is added to tsftimer so sync with transmission. 
     */
    tsftimer = (tsftimer + 2000000) / 1000;
    printf("Received tsfTimer = %llu \n", tsftimer);
    setTsfTimer(tsftimer);
    return 1;
}

void sig_int(void) {
    int ret;
    int sem_val;

    removeUser(pid, &entry);
    ret = sem_getvalue(&indication_sem, &sem_val);
    if (ret <= 0)
        sem_post(&indication_sem);
    sem_destroy(&indication_sem);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);

}

void sig_term(void) {
    removeUser(pid, &entry);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);
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
            memcpy(data, (char *) argname, sizeof(u_int8_t));
            break;
    }
}
