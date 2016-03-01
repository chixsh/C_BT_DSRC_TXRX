#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termio.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include "wave.h"
#include <pthread.h>
#include <semaphore.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#define MAX_RSP 50

static int pid;
static uint64_t count = 0, blank = 0;
char addr1[18];
sem_t addr;
WSMIndication rxpkt;

extern void *main_bluetooth(void *);

extern int bt_write(char *, int);

extern void sig_int_bluetooth(void);

pthread_t bluethread = 0;
int Btooth_forward = 0;

// User with ACID = 1 and ACM = demo
void sig_int(void);

void sig_term(void);

//static USTEntry entry;
static WMEApplicationRequest entry;

int confirmBeforeJoin(WMEApplicationIndication *);

void set_args(void *, void *, int);

enum {
    ADDR_MAC = 0, UINT8
};
struct arguments {
    u_int8_t macaddr[17];
    u_int8_t channel;
};


int main(int arg, char *argv[]) {
    struct arguments arg1;
    int thread_ret = -1, thread_arg = 2;
    int rx_ret = -1, btooth_ret = -1;

    if (arg < 4) {
        printf("usage: bluetoothrx [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [channel <optional>] [PROVIDER MAC <optional>]\n");
        return 0;
    }

    thread_ret = pthread_create(&bluethread, NULL, main_bluetooth, (void *) &thread_arg);
    sched_yield();
    if (thread_ret < 0) {
        printf("\nERROR : main_bluethread not created\n");
        exit(1);
    }
    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);

    registerLinkConfirm(confirmBeforeJoin);
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

    while (1) { // starts rx packets and tx to bluetooth socket
        rx_ret = rxWSMPacket(pid, &rxpkt); // rx wsmp pkt
        sched_yield();
        usleep(100000);
        if (rx_ret > 0) {
            printf("Received WSMP Packet txpower= %d, rateindex=%d Packet No =#%llu#\n", rxpkt.chaninfo.txpower,
                   rxpkt.chaninfo.rate, count++);
            memcpy(addr1, rxpkt.data.contents, rxpkt.data.length);

            if (Btooth_forward == 1) {
                btooth_ret = bt_write(addr1, rxpkt.data.length); // write to bluetooth socket
            }
            else {
                printf("No Andriod application running \n");
            }
        }//if
        else {
            blank++;
            //printf("\nRX pkts failed\n");
        }
    }//while
    return 0;
}

void sig_int(void) {

    removeUser(pid, &entry);
    pthread_cancel(bluethread);

    sig_int_bluetooth();

    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);

}

void sig_term(void) {
    sig_int();
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




