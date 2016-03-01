//
// Created by TRL on 2/12/2016.
//
#include "DSRC_Handler.h"
#include "Bluetooth_Handler.h"

static int pid;
//static USTEntry entry;
static WMEApplicationRequest entry;
static uint64_t count = 0, blank = 0;


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
            if (Extract_MAC_Acaddress(data, string) < 0) {
                printf("invalid address\n");
            }
            break;
        case UINT8:

            //temp = atoi(argument1->channel);
            memcpy(data, (char *) argname, sizeof(u_int8_t));
            break;
    }
}


int Extract_MAC_Address(u_int8_t *mac, char *str) {
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

int Initialize_DSRC_Environment(int arg, char *argv[]) {
    struct arguments arg1;
    memset(&DSRC_Entry, 0, sizeof(WMEApplicationRequest));
    DSRC_Entry.psid = atoi(argv[4]);

    if ((atoi(argv[1]) > USER_REQ_SCH_ACCESS_NONE) || (atoi(argv[1]) < USER_REQ_SCH_ACCESS_AUTO)) {
        printf("User request type invalid: setting default to auto\n");
        DSRC_Entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
    } else {
        DSRC_Entry.userreqtype = atoi(argv[1]);
    }
    if (DSRC_Entry.userreqtype == USER_REQ_SCH_ACCESS_AUTO_UNCONDITIONAL) {
        if (arg < 5) {
            printf("channel needed for unconditional access\n");
            exit(0);
        } else {
            DSRC_Entry.channel = atoi(argv[5]);
        }
    }
    DSRC_Entry.schaccess = atoi(argv[2]);
    DSRC_Entry.schextaccess = atoi(argv[3]);
    if (arg > 6) {
        strncpy(arg1.macaddr, argv[6], 17);
        DSRC_Set_Arguments(DSRC_Entry.macaddr, &arg1, ADDR_MAC);
    }

    /* if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
         printf("Open Failed. Quitting\n");
         exit(-1);
     }*/

    int pid = DSRC_Entry.psid;
    printf("Registering DSRC User %d\n", DSRC_Entry.psid);
    if (registerUser(pid, &DSRC_Entry) < 0) {
        printf("Register DSRC User Failed \n");
        printf("Removing DSRC user if already present  %d\n", !removeUser(pid, &DSRC_Entry));
        printf("DSRC USER Registered %d with PSID =%u \n", registerUser(pid, &DSRC_Entry), DSRC_Entry.psid);
    }

}
























