//
// Created by TRL on 2/12/2016.
//
#include "Bluetooth_Handler.h"
#include "DSRC_Handler.h"


static int pid;
//static USTEntry entry;
static WMEApplicationRequest entry;
static uint64_t count = 0, blank = 0;

int rx_ret = -1, btooth_ret = -1;
WSMMessage rxmsg;

static WSMRequest MessageForSending;

WSMIndication rxpkt;
int ret = 0;
pthread_t DSRC_Thread = 0;

#define _FF000000 4278190080;
#define _00FF0000 16711680;
#define _0000FF00 65280;
#define _000000FF 255;

#define _0_Bytes 0;
#define _1_Bytes 8;
#define _2_Bytes 16;
#define _3_Bytes 24;


#define _F0 240;
#define _0F 15;


char Result[2];


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

int Initialize_DSRC_RX_Environment(int arg, char *argv[]) {

    rxmsg.wsmIndication = &rxpkt;

    struct arguments arg1;
    memset(&DSRC_RX_Entry, 0, sizeof(WMEApplicationRequest));
    DSRC_RX_Entry.psid = atoi(argv[4]);

    if ((atoi(argv[1]) > USER_REQ_SCH_ACCESS_NONE) || (atoi(argv[1]) < USER_REQ_SCH_ACCESS_AUTO)) {
        printf("User request type invalid: setting default to auto\n");
        DSRC_RX_Entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
    } else {
        DSRC_RX_Entry.userreqtype = atoi(argv[1]);
    }
    if (DSRC_RX_Entry.userreqtype == USER_REQ_SCH_ACCESS_AUTO_UNCONDITIONAL) {
        if (arg < 5) {
            printf("channel needed for unconditional access\n");
            exit(0);
        } else {
            DSRC_RX_Entry.channel = atoi(argv[5]);
        }
    }
    DSRC_RX_Entry.schaccess = atoi(argv[2]);
    DSRC_RX_Entry.schextaccess = atoi(argv[3]);
    if (arg > 6) {
        strncpy(arg1.macaddr, argv[6], 17);
        DSRC_Set_Arguments(DSRC_RX_Entry.macaddr, &arg1, ADDR_MAC);
    }

    /* if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
         printf("Open Failed. Quitting\n");
         exit(-1);
     }*/

    int pid = getpid();
    printf("Registering DSRC User %d\n", DSRC_RX_Entry.psid);
    if (registerUser(pid, &DSRC_RX_Entry) < 0) {
        printf("Register DSRC User Failed \n");
        printf("Removing DSRC user if already present  %d\n", !removeUser(pid, &DSRC_RX_Entry));
        printf("DSRC USER Registered %d with PSID =%u \n", registerUser(pid, &DSRC_RX_Entry), DSRC_RX_Entry.psid);
    }
}

int Initialize_DSRC_TX_Environment(int arg, char *argv[]) {

    rxmsg.wsmIndication = &rxpkt;

    struct arguments arg1;
    memset(&DSRC_TX_Entry, 0, sizeof(WMEApplicationRequest));
    DSRC_TX_Entry.psid = atoi(argv[4]);

    if ((atoi(argv[1]) > USER_REQ_SCH_ACCESS_NONE) || (atoi(argv[1]) < USER_REQ_SCH_ACCESS_AUTO)) {
        printf("User request type invalid: setting default to auto\n");
        DSRC_TX_Entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
    } else {
        DSRC_TX_Entry.userreqtype = atoi(argv[1]);
    }
    if (DSRC_TX_Entry.userreqtype == USER_REQ_SCH_ACCESS_AUTO_UNCONDITIONAL) {
        if (arg < 5) {
            printf("channel needed for unconditional access\n");
            exit(0);
        } else {
            DSRC_TX_Entry.channel = atoi(argv[5]);
        }
    }
    DSRC_TX_Entry.schaccess = atoi(argv[2]);
    DSRC_TX_Entry.schextaccess = atoi(argv[3]);
    if (arg > 6) {
        strncpy(arg1.macaddr, argv[6], 17);
        DSRC_Set_Arguments(DSRC_TX_Entry.macaddr, &arg1, ADDR_MAC);
    }

    /* if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
         printf("Open Failed. Quitting\n");
         exit(-1);
     }*/

    int pid = getpid();

    printf("Registering DSRC User %d\n", DSRC_TX_Entry.psid);
    if (registerProvider(pid, &DSRC_TX_Entry) < 0) {
        printf("Register DSRC Provider Failed \n");
        printf("Removing DSRC Provider if already present  %d\n", !removeProvider(pid, &DSRC_TX_Entry));
        printf("DSRC Provider Registered %d with PSID =%u \n", registerProvider(pid, &DSRC_TX_Entry),
               DSRC_TX_Entry.psid);
    } else {
        printf("provider registered with PSID = %u\n", DSRC_TX_Entry.psid);
    }

}


char *Dec2Hex(short Number) {
    Result[0] = '0';
    Result[1] = '0';

    // printf("Dec2Hex. Number = %d :- Starting \n", Number);

    short N_0 = Number & _F0;
    N_0 = N_0 >> 4;
    short N_1 = Number & _0F;

    //  printf("\t short  N_0 = Number & F0. = %d ", N_0);
    //  printf("\t short  N_1 = Number & 0F. = %d \n", N_1);


    if (N_0 < 10) {
        Result[0] = N_0 + 48;
        //     printf("\t\t  N_0 < 10.  N_0 + 48. as Char = %c\n", Result[0]);
    }
    else {
        Result[0] = N_0 + 55;
        //    printf("\t\t  N_0 >= 10.  N_0 + 55. as Char = %c\n", Result[0]);
    }
    if (N_1 < 10) {
        Result[1] = N_1 + 48;
        //    printf("\t\t  N_1 < 10.  N_1 + 48. as Char = %c\n", Result[1]);
    }
    else {
        Result[1] = N_1 + 55;
        //   printf("\t\t  N_1 >= 10.  N_1 + 55. as Char = %c\n", Result[1]);
    }

    //  printf("Dec2Hex. Number = %d :- Ended With Result %s \n", Number, Result);
    return Result;
}


int longLatToFourBytes(double LongLat, BasicSafetyMessage_t *bsm, int Start) {

    // printf("longLatToFourBytes. LongLat = %lf :- Starting \n", LongLat);

    ulong Number = (ulong)(LongLat * 10000000);

    //  printf("\tulong Number = LongLat * 10000000. = %ld ", Number);
    if (Number < 0) {
        //     printf("\tNumber is -ve. Adding .4294967296  = %ld \n", Number);
        Number = Number + 4294967296;
    } else {
        //    printf("\tNumber is +ve. No Change  = %ld \n", Number);
    }


/*
 *
 * #define _FF000000 4278190080;
 * #define _00FF0000 16711680;
 * #define _0000FF00 65280;
 * #define _000000FF 255;
 *
 *
 * #define _0_Bytes 0;
 * #define _2_Bytes 16;
 * #define _4_Bytes 32;
 * #define _6_Bytes 48;
 *
 *
 */

    ulong N_0 = Number & _FF000000;
    //  printf("\t\tulong N_0  = %ld & FF000000 = %ld \t", Number, N_0);
    N_0 = N_0 >> _3_Bytes; // Shift Right 6 Bytes
    // printf("Shift N_0 Right 3 Bytes    = %ld\n", N_0);

    ulong N_1 = Number & _00FF0000;
    // printf("\t\tulong N_1  = %ld & 00FF0000 = %ld  \t", Number, N_1);
    N_1 = N_1 >> _2_Bytes; // Shift Right 4 Bytes
    // printf("Shift N_1 Right 2 Bytes    = %ld\n", N_1);

    ulong N_2 = Number & _0000FF00;
    // printf("\t\tulong N_2  = %ld & 0000FF00 = %ld  \t", Number, N_2);
    N_2 = N_2 >> _1_Bytes; // Shift Right 2 Bytes
    //  printf("Shift N_2 Right 1 Bytes    = %ld\n", N_2);

    ulong N_3 = Number & _000000FF;
    // printf("\t\tulong N_3  = %ld & 000000FF = %ld  \t", Number, N_3);
    N_3 = N_3 >> _0_Bytes; // Shift Right 0 Bytes
    // printf("Shift N_3 Right 0 Bytes    = %ld\n", N_3);


    //           MS       LS
    // Octect =  N0 N1 N2 N3

    bsm->blob1.buf[Start + 0] = N_0;
    bsm->blob1.buf[Start + 1] = N_1;
    bsm->blob1.buf[Start + 2] = N_2;
    bsm->blob1.buf[Start + 3] = N_3;

}

int FillGPSInfo(BasicSafetyMessage_t *bsm) {
    static int count = 0;
    count++;                   /* count for the Number of packets Tx */
    int j;
    //  printf("FillGPSInfo :- Starting \n");

    bsm->msgID.size = sizeof(uint8_t);
    bsm->msgID.buf[0] = DSRCmsgID_basicSafetyMessage; // Choose what type of message you want to transfer
    bsm->blob1.buf = (uint8_t *) calloc(1, 38 * sizeof(uint8_t)); // Allocate the memory for the blob buffer

    bsm->blob1.size = 38 * sizeof(uint8_t);
    for (j = 0; j < 38; j++) {
        bsm->blob1.buf[j] = j; /* We are filling some dummy data because of It is a Sample application */
    }
    bsm->blob1.buf[0] = count % 1000;


    char *GPSAddress = get_gpsc_devaddr();
    get_gps_status(&gpsdata, GPSAddress);

    GPSData *GPS = &gpsdata;


    longLatToFourBytes(GPS->latitude, bsm, 07); // Update Latitude Bytes
    longLatToFourBytes(GPS->longitude, bsm, 11); // Update Latitude Bytes

    //   printf("FillGPSInfo :- Ended \n");
}

int BuildMessage() {
    int j;

    asn_enc_rval_t rvalenc;


    /* WSM Channel and Tx info */
    MessageForSending.chaninfo.channel = 172;
    MessageForSending.chaninfo.rate = 3;
    MessageForSending.chaninfo.txpower = 15;
    MessageForSending.version = 1;
    MessageForSending.security = 1;
    MessageForSending.psid = 10;
    MessageForSending.txpriority = 1;
    memset(&MessageForSending.data, 0, sizeof(WSMData));
    /* BSM related information */
    BasicSafetyMessage_t *bsm; /* BSM Data structure declaration */
    bsm = (BasicSafetyMessage_t *) calloc(1, sizeof(*bsm));
    bsm->msgID.buf = (uint8_t *) calloc(1,
                                        sizeof(uint8_t)); // allocate memory for buffer which is used to store, what type of message it is


    FillGPSInfo(bsm);

    rvalenc = der_encode_to_buffer(&asn_DEF_BasicSafetyMessage, bsm, &MessageForSending.data.contents,
                                   1000); // Encode your BSM in to WSM Packets
    if (rvalenc.encoded == -1) {
        fprintf(stderr, "Cannot encode %s: %s\n", rvalenc.failed_type->name, strerror(errno));
    } else {
        //  printf("Structure successfully encoded %d\n", rvalenc.encoded);
        MessageForSending.data.length = rvalenc.encoded;
        asn_DEF_BasicSafetyMessage.free_struct(&asn_DEF_BasicSafetyMessage, bsm, 0);
    }
    return 1;
}

int TransmitMessage() {

    ret = txWSMPacket(pid, &MessageForSending);

}

int Send_DSRC_Message() {

    BuildMessage();

    TransmitMessage();

    return SEND_DSRC_MESSAGE;
}

int Receive_DSRC_Message() {

    rx_ret = rxWSMMessage(pid, &rxmsg); /* Function to receive the Data from TX application */
    sched_yield();

    if (rx_ret > 0) {
        printf("Received DSRC Message txpower= %d, rateindex=%d Packet No =#%llu#\n", rxpkt.chaninfo.txpower,
               rxpkt.chaninfo.rate, Bluetooth_Count++);
        rxWSMIdentity(&rxmsg, 0); //Identify the type of received Wave Short Message.
        if (!rxmsg.decode_status) {
            Decode_BSM_Message_And_Forward_It_To_BlueTooth_Device(rxmsg);
            xml_print(rxmsg); /* call the parsing function to extract the contents of the received message */
        }
    }//if
    else {
        Bluetooth_Blank++;
    }

    return RECEIVE_DSRC_MESSAGE;
}


int SendReceive() {

    int LastOperation = RECEIVE_DSRC_MESSAGE;

    printf("Start Send and Receive of DSRC Messages \n");
    while (1) {

        usleep(1000);
        if (LastOperation == SEND_DSRC_MESSAGE) { LastOperation = Receive_DSRC_Message(); }
        else { LastOperation = Send_DSRC_Message(); }

    }//while
}
