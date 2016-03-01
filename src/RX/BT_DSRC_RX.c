//
// Created by trl on 2/12/16.
//

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
#include <syslog.h>
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
#include <asnwave.h>
#include <BasicSafetyMessage.h>
#include<netinet/tcp.h> //for TCP_NODELAY

static struct sockaddr_in gpsc_devaddr;
static int is_gpsc_devaddr_set = 0;
#define DEFAULT_DEVADDR "127.0.0.1"

int gpscsockfd = -1;
static int pid;
static uint64_t count = 0, blank = 0;
char addr1[1024];

static GPSData gpsdata;

//static int gpstxdelay = 0;
#define MILLION 1000000
#define RATESET_NUM_ELMS 12
#define DEFAULT_TXDELAY 50
#define DEFAULT_CHAN 178
#define DEFAULT_VAP "ath0"
#define DEFAULT_POWER 22
#define DEFAULT_RATE  9.0f

static long gps_txdelay = DEFAULT_TXDELAY;
static int gps_txpower = DEFAULT_POWER;
static int gps_txchannel = DEFAULT_CHAN;
static float gps_txrate = DEFAULT_RATE;
static char gps_vap[10];

static int contents = 0;
static int dump_gpsd = 0;
static float rate_set[] = {0.0f, 3.0f, 4.5f, 6.0f, 9.0f, 12.0f, 18.0f, 24.0f, 27.0f, 36.0f, 48.0f, 54.0f};
static int firstchan = 1, firstrate = 1, firstpower = 1;
static int isVAPset = 0;
static int isNotWSMP = 0;
static char data_sys[25];

int parseGPSBinData(GPSData *gps, char *str, int len);

char *set_gpsc_devaddr(char *devaddr);

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
static WMEApplicationRequest BT_Entry;
static WMEApplicationRequest DSRC_Entry;
static WSMRequest wsmtxreq;

enum {
    ADDR_MAC = 0, UINT8
};
struct arguments {
    u_int8_t macaddr[17];
    u_int8_t channel;
};


void BT_Signal_Interrupt(void) {

    removeUser(pid, &BT_Entry);
    pthread_cancel(bluethread);

    sig_int_bluetooth();

    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets received = %llu\n", count);
    printf("Blank Poll = %llu\n", blank);
    printf("remoterx killed by kill signal\n");
    exit(0);

}

void BT_Signal_Terminate(void) {
    BT_Signal_Interrupt();
}


int BT_ConfirmBeforeJoin(WMEApplicationIndication *appind) {
    printf("\nJoin\n");
    return 1; /* Return 0 for NOT Joining the WBSS */
}


void BT_Set_Arguments(void *data, void *argname, int datatype) {
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


int Extract_MAC_Acaddress(u_int8_t *mac, char *str) {
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

int isBigEndian() {
    long one = 0x00000001;
    return !(*((char *) (&one)));
}


long get_gps_txdelay() {
    return gps_txdelay;
}

int get_gps_txpower() {
    return gps_txpower;
}

int get_gps_txchannel() {
    return gps_txchannel;
}

float get_gps_txrate() {
    return gps_txrate;
}

char *get_gps_vap() {
    return gps_vap;
}

int __extract_rate(char *str) {
    int i = 0, numdots = 0;
    int len = strlen(str);
    float rate = 0.0f;
    for (i = 0; i < len; i++) {
        if ((!isdigit(str[i])) && (str[i] != '.'))
            return -1;

        if (str[i] == '.')
            numdots++;

        if (numdots > 1)
            return -1;
    }
    sscanf(str, "%f", &rate);

    if (rate <= 0.0f)
        return -1;

    for (i = 1; i < RATESET_NUM_ELMS; i++) {
        if (rate_set[i] == rate)
            return i;
    }

    return -1;
}

float __set_vap_txrate() {
    sprintf(data_sys, "iwconfig %s rate %fM", get_gps_vap(), get_gps_txrate());
    printf("%s\n", data_sys);
    system(data_sys);
    return gps_txrate;
}


int __set_vap_txpower() {
    sprintf(data_sys, "iwconfig %s txpower %d", get_gps_vap(), get_gps_txpower());
    printf("%s\n", data_sys);
    system(data_sys);
    return gps_txpower;
}

int __set_vap_txchannel() {
    sprintf(data_sys, "iwconfig %s channel %d", get_gps_vap(), get_gps_txchannel());
    printf("%s\n", data_sys);
    system(data_sys);
    return gps_txchannel;
}

int parseTXConfigData(WSMRequest *wsmtxreq) {
    FILE *file;
    char configstr[250], *token;// str[25],
    int prev = 0;
    int temp;
    float tempf;
    enum {
        POWER = 1, RATE, CHAN, DELAY, VAP
    };

    if (!isVAPset) {
        memcpy(gps_vap, DEFAULT_VAP, 10);
        isVAPset = 1;
    }

    if (wsmtxreq == NULL)
        return 1;
#ifdef WIN32
    {
        char logfilename[100];
        strcpy (logfilename, getenv("WINDIR"));
        strcat (logfilename, GPSCONFIG);
        file = fopen(logfilename, "r");
    }
#else
    file = fopen(GPSCONFIG, "r");
#endif
    if (file == NULL) {

        return 1;
    }

    if (fgets(configstr, 200, file) < 0) {

        return 2;
    }
    fclose(file);

    configstr[strlen(configstr) - 1] = '\0';
    token = (char *) strtok(configstr, " \n");
    do {
        if (token == NULL)
            return 0;

        if (!strcasecmp(token, "X_POWER")) {
            prev = POWER;
        } else if (!strcasecmp(token, "X_RATE")) {
            prev = RATE;
        } else if (!strcasecmp(token, "X_CHAN")) {
            prev = CHAN;
        } else if (!strcasecmp(token, "X_DELAY")) {
            prev = DELAY;
        } else if (!strcasecmp(token, "X_VAP")) {
            prev = VAP;
        } else {
            switch (prev) {
                case POWER:
                    sscanf(token, "%d", &temp);
                    if (isNotWSMP) {
                        if (firstpower) {
                            gps_txpower = (uint8_t)((temp + 1) / 2);
                            __set_vap_txpower();
                            firstpower = 0;
                        } else if (gps_txpower != (uint8_t)((temp + 1) / 2)) {
                            gps_txpower = (uint8_t)((temp + 1) / 2);
                            __set_vap_txpower();
                        }
                        gps_txpower = (uint8_t)((temp + 1) / 2);
                    }
                    wsmtxreq->chaninfo.txpower = (u_int8_t) temp;
                    temp = 0;
                    prev = 0;
                    break;

                case RATE:
                    temp = __extract_rate(token);
                    if (temp >= 0)
                        wsmtxreq->chaninfo.rate = (u_int8_t) temp;
                    if (isNotWSMP) {
                        sscanf(token, "%f", &tempf);
                        if (firstrate) {
                            gps_txrate = tempf;
                            __set_vap_txrate();
                            firstrate = 0;
                        } else if (gps_txrate != tempf) {
                            gps_txrate = tempf;
                            __set_vap_txrate();
                        }
                        gps_txrate = (float) tempf;
                    }
                    temp = 0;
                    tempf = 0.0f;
                    prev = 0;
                    break;

                case CHAN:
                    sscanf(token, "%d", &temp);
                    if (firstchan) {
                        gps_txchannel = temp;
                        __set_vap_txchannel();
                        firstchan = 0;
                    } else if (gps_txchannel != temp) {
                        gps_txchannel = temp;
                        __set_vap_txchannel();
                    }
                    wsmtxreq->chaninfo.channel = (u_int8_t) temp;
                    gps_txchannel = temp;
                    temp = 0;
                    prev = 0;
                    break;

                case DELAY:
                    sscanf(token, "%d", &temp);
                    gps_txdelay = (long) temp;
                    temp = 0;
                    prev = 0;
                    break;

                case VAP:
                    strncpy(gps_vap, token, 10);
                    break;

                default:
                    prev = 0;
            }

        }
        token = (char *) strtok(NULL, " ");
    } while (token != NULL);


    return 0;
}

char *get_gpsc_devaddr() {
    if (is_gpsc_devaddr_set)
        return inet_ntoa(gpsc_devaddr.sin_addr);
    else
        return (char *) DEFAULT_DEVADDR;
}

int gpsc_connect(char *ip) {
    int ret, one = 1;
    struct sockaddr_in gpsdaddr;
    int flags;

    if (gpscsockfd > 0)
        return gpscsockfd;

    if ((gpscsockfd = socket(AF_INET, SOCK_STREAM, 6)) < 0) {
        (void) syslog(LOG_ERR, "gpsc %d\n", __LINE__);
        return -1;
    }

    if (gpscsockfd > 0) {
        bzero(&gpsdaddr, sizeof(gpsdaddr));

        if (!is_gpsc_devaddr_set)
            set_gpsc_devaddr(ip);

        gpsdaddr.sin_addr = gpsc_devaddr.sin_addr;
        gpsdaddr.sin_family = AF_INET;
        gpsdaddr.sin_port = htons(8947);

        if (setsockopt(gpscsockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
            (void) syslog(LOG_ERR, "gpsc %d\n", __LINE__);
            gpsc_close_sock();
            return -2;
        }
        if (setsockopt(gpscsockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1) {
            (void) syslog(LOG_ERR, "gpsc %d\n", __LINE__);
            gpsc_close_sock();
            return -2;
        }
        ret = connect(gpscsockfd, (struct sockaddr *) &gpsdaddr, sizeof(gpsdaddr));
        if (ret < 0) {
            (void) syslog(LOG_ERR, "gpsc %d\n", __LINE__);
            gpsc_close_sock();
            (void) syslog(LOG_ERR, "failing on connect to gpsc\n");
            return -2;
        }
    }
    return gpscsockfd;
}

int gpsc_close_sock() {
    close(gpscsockfd);
    gpscsockfd = -1;
    return 0;
}

char *set_gpsc_devaddr(char *devaddr) {
    int ret;
    is_gpsc_devaddr_set = 0;
#ifdef WIN32
    gpsc_devaddr.sin_addr.s_addr = inet_addr ((devaddr)? devaddr : (char*)DEFAULT_DEVADDR);
#else
    ret = inet_aton((devaddr) ? devaddr : (char *) DEFAULT_DEVADDR, &gpsc_devaddr.sin_addr);
#endif
    if (!ret)
        return NULL;
    is_gpsc_devaddr_set = 1;
    return (devaddr) ? devaddr : (char *) DEFAULT_DEVADDR;
}

void get_gps_status(GPSData *gpsdat, char *gpsadd) {
    int skfd = 0;
    char ch = '1';
    (void) gpsc_connect(gpsadd);
    write(gpscsockfd, &ch, 1);
    read(gpscsockfd, gpsdat, sizeof(GPSData));
    gpsc_close_sock();
}

int Decode_BSM_Message_And_Forward_It_To_BlueTooth_Device(WSMMessage rxmsg) {

    uint32_t longitude_val;
    uint32_t latitude_val;
    uint16_t altitude_val;
    uint16_t speed_val;
    uint16_t heading_val;
    uint8_t year_val, month_val, day_val;
    uint8_t valid_bsm = 0;
    int ret = 0;//, i = 0;
    struct FullPositionVector *fpv;
    void *Logdata;
    uint32_t temp_var;
    BasicSafetyMessage_t *bsmLog;
    if (rxmsg.type == WSMMSG_BSM) {
        valid_bsm = 1;
        bsmLog = (BasicSafetyMessage_t *) rxmsg.structure;
        memcpy(&latitude_val, bsmLog->blob1.buf + 7, 4);
        temp_var = (uint32_t) htobe32((uint32_t) latitude_val);
        latitude_val = temp_var;
        memcpy(&longitude_val, bsmLog->blob1.buf + 11, 4);
        temp_var = longitude_val;
        longitude_val = htobe32(temp_var);
        memcpy(&altitude_val, bsmLog->blob1.buf + 15, 2);
        memcpy(&speed_val, bsmLog->blob1.buf + 21, 2);
        memcpy(&heading_val, bsmLog->blob1.buf + 23, 2);
/*
        if (bsmLog->status != NULL) {
            Logdata = (void *) (bsmLog->status->fullPos);
            printf("77\n\r");
            fpv = (struct FullPositionVector *) Logdata;
            year_val = *(fpv->utcTime->year);
            month_val = *(fpv->utcTime->month);
            day_val = *(fpv->utcTime->day);
            printf("88\n\r");
        }
*/
        ret = 1;

        int btooth_ret = -1;


        if (Btooth_forward == 1) {


            //  printf("11\n\r");


            memset(&wsmtxreq, 0, sizeof(WSMRequest));


            char *GPSAddress = get_gpsc_devaddr();
            get_gps_status(&gpsdata, GPSAddress);

            GPSData *GPS = &gpsdata;
            /*build_gps_wsmpacket(0, &wsmtxreq, &GPS, TX_GPS);*/

            //  printf("22\n\r");

            char GPSDATA[100];
            sprintf(GPSDATA, "lat:%lf,lon:%lf,alt:%lf,speed:%lf,", GPS->latitude, GPS->longitude, GPS->altitude,
                    GPS->speed);
            // printf("33\n\r");
            int GPSDATASize = strlen(GPSDATA);

            //  printf("GPSDATA[%d]: lat:%lf,lon:%lf,alt:%lf,speed:%lf\n\r",StrSize, GPS->latitude,GPS->longitude,GPS->altitude,GPS->speed);


            printf("GPSDATA[%d]: %s\n\r", GPSDATASize, GPSDATA);


            char Message[1024];
            // Message   =  strcat(strcat(GPSDATA, "/"), addr1);

            int BlobSize = 38;

            //memcpy(addr1, bsmLog->blob1.buf, 38);

            memcpy(Message, bsmLog->blob1.buf, 38);
            memcpy(Message + 38, GPSDATA, GPSDATASize);

            int MessageSize = strlen(Message);
            printf("Forwarded Message[%d]: %s\n\r", GPSDATASize + 38, Message);

            btooth_ret = bt_write(Message, GPSDATASize + 38); // write to bluetooth socket
            //  printf("Message Forwared to Phone\n\r");
        }
        else {
            printf("No Andriod application running \n");
        }

    }
    return ret;
}

int main(int arg, char *argv[]) {
    struct arguments arg1;
    int thread_ret = -1, thread_arg = 2;
    int rx_ret = -1, btooth_ret = -1;


    WSMMessage rxmsg;
    WSMIndication rxpkt;
    //int i, attempts = 10, drops = 0, result;
    int ret = 0;
    rxmsg.wsmIndication = &rxpkt;


    if (arg < 5) {
        printf("usage: bluetoothrx [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [PSID] [channel] [PROVIDER MAC <optional>]\n");
        return 0;
    }

    thread_ret = pthread_create(&bluethread, NULL, main_bluetooth, (void *) &thread_arg);
    sched_yield();
    if (thread_ret < 0) {
        printf("\nERROR : main_bluethread not created\n");
        exit(1);
    }
    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) BT_Signal_Interrupt);
    signal(SIGTERM, (void *) BT_Signal_Terminate);

    registerLinkConfirm(BT_ConfirmBeforeJoin);
    pid = getpid();
    memset(&BT_Entry, 0, sizeof(WMEApplicationRequest));
    BT_Entry.psid = 10;

    memset(&DSRC_Entry, 0, sizeof(WMEApplicationRequest));

    DSRC_Entry.psid = atoi(argv[4]);

    if ((atoi(argv[1]) > USER_REQ_SCH_ACCESS_NONE) || (atoi(argv[1]) < USER_REQ_SCH_ACCESS_AUTO)) {
        printf("User request type invalid: setting default to auto\n");
        BT_Entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
        DSRC_Entry.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
    } else {
        BT_Entry.userreqtype = atoi(argv[1]);
        DSRC_Entry.userreqtype = atoi(argv[1]);
    }
    if (BT_Entry.userreqtype == USER_REQ_SCH_ACCESS_AUTO_UNCONDITIONAL) {
        if (arg < 5) {
            printf("channel needed for unconditional access\n");
            return 0;
        } else {
            BT_Entry.channel = atoi(argv[5]);
            // Channel ID Might need to be different
            DSRC_Entry.channel = atoi(argv[5]);
        }
    }

    BT_Entry.schaccess = atoi(argv[2]);
    BT_Entry.schextaccess = atoi(argv[3]);

    DSRC_Entry.schaccess = atoi(argv[2]);
    DSRC_Entry.schextaccess = atoi(argv[3]);

    if (arg > 6) {
        strncpy(arg1.macaddr, argv[6], 17);
        BT_Set_Arguments(BT_Entry.macaddr, &arg1, ADDR_MAC);

        DSRC_Set_Arguments(DSRC_Entry.macaddr, &arg1, ADDR_MAC);
    }
    printf("Invoking WAVE driver \n");

    if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
        printf("Open Failed. Quitting\n");
        exit(-1);
    }

    /* printf("Registering Bluetooth User %d\n", BT_Entry.psid);
     if (registerUser(pid, &BT_Entry) < 0) {
         printf("Register Bluetooth User Failed \n");
         printf("Removing Bluetooth user if already present  %d\n", !removeUser(pid, &BT_Entry));
         printf("Bluetooth USER Registered %d with PSID =%u \n", registerUser(pid, &BT_Entry), BT_Entry.psid);
     }*/

    printf("Registering DSRC User %d\n", DSRC_Entry.psid);
    if (registerUser(pid, &DSRC_Entry) < 0) {
        printf("Register DSRC User Failed \n");
        printf("Removing DSRC user if already present  %d\n", !removeUser(pid, &DSRC_Entry));
        printf("DSRC USER Registered %d with PSID =%u \n", registerUser(pid, &DSRC_Entry), DSRC_Entry.psid);
    }

    while (1) { // starts rx packets and tx to bluetooth socket
        // rx_ret = rxWSMPacket(pid, &rxpkt); // rx wsmp pkt
        rx_ret = rxWSMMessage(pid, &rxmsg); /* Function to receive the Data from TX application */
        sched_yield();
        usleep(100000);
        if (rx_ret > 0) {
            printf("Received DSRC Message txpower= %d, rateindex=%d Packet No =#%llu#\n", rxpkt.chaninfo.txpower,
                   rxpkt.chaninfo.rate, count++);


            rxWSMIdentity(&rxmsg, 0); //Identify the type of received Wave Short Message.


            if (!rxmsg.decode_status) {
                Decode_BSM_Message_And_Forward_It_To_BlueTooth_Device(rxmsg);

                xml_print(rxmsg); /* call the parsing function to extract the contents of the received message */
            }

            //rxmsg.wsmIndication = &rxpkt;
            /*memcpy(addr1,rxpkt.data.contents,rxpkt.data.length);

            if(Btooth_forward == 1){
                btooth_ret = bt_write(addr1,rxpkt.data.length); // write to bluetooth socket
            }
            else {
                printf("No Andriod application running \n");
            }*/
        }//if
        else {
            blank++;
            //printf("\nRX pkts failed\n");
        }
    }//while
    return 0;
}
