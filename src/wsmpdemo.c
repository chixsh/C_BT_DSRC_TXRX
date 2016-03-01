/*

* Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

* Proprietary and Confidential Material.

*

*/

#include <stdio.h>
#include <ctype.h>
#include <termio.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <wave.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <linux/wireless.h>
#include <getopt.h>
#include "wavelogger.h"
#include <BasicSafetyMessage.h>
#include <asnwave.h>
#include "wave.h"

#define PERMS 0664
#define WSMP_MAX_MSG_LEN 600
#define MAXRXPKTS 100
#define FIXEDLEN 6
#define MYPORT 4950
#define IPPORT 8756
#define MAXBUFLEN 2048
#define SIOCGIWSTATS 0x8B0F

extern int AsnLog(int, uint8_t, int, int, char *, void *, void *, double, uint16_t);

enum {
    BOOL, UINT8, UINT16, UINT32, UINT64, STRING, STRINGLONG, ADDR_MAC, ADDR_IPV4, ADDR_IPV6, RATESET
};

#define UINT8MAX 255
#define UINT16MAX 65535
#define UINT32MAX 4294967295UL
#define UINT64MAX 18446744073709551615
#define RATESET_NUM_ELMS 12

float rate_set[] = {0.0f, 3.0f, 4.5f, 6.0f, 9.0f, 12.0f, 18.0f, 24.0f, 27.0f, 36.0f, 48.0f, 54.0f};

#define DEFAULT_ACM "default_acm"
#define DEFAULT_WSM "default_wsm"
#define DEFAULT_LOGFILE "/etc/wsmpdemo.log"
#define DEFAULT_TXDELAY 10

static int ipvfour = -1;
char logbuf_t[MAXBUFLEN];
//static WSMPacket wsmtxpkt;
static WSMRequest wsmtxreq;
static WMETARequest tareq;
//static WSMPacket wsmrxpkt;
static WSMIndication wsmrxind;
static WSMIndication rxpkt;
//static IPPacket ippacket;
static additionalWSMP addwsmp;

int AsmDecodeContentType(WSMIndication *rxpkt);

uint32_t longitude_val;
uint32_t latitude_val;
uint16_t altitude_val;
uint16_t speed_val;
uint16_t heading_val;
uint8_t year_val, month_val, day_val;
static WSMMessage rxmsg;

uint8_t valid_bsm = 0;
static int wbss_psid = 0;
static int wsmp_psid = 0;
static GPSData gpsdata;
static GPSData rxgpsdata;
static u_int16_t txrepeat = 1;
static u_int32_t txdelay = DEFAULT_TXDELAY;

static u_int16_t numtx = 0;
static u_int64_t numrx = 0;
static u_int16_t numdropped = 0;
static u_int32_t sizetx = 0;
static u_int64_t sizerx = 0;
//static u_int16_t rxpktnum = 0;
//static u_int16_t rxdispnum = 0;

static u_int16_t pid;
static u_int8_t usrReqFlag = 0;

enum {
    UNSECURED, SECURED, ENCRYPTED
};//SECURITY TYPE


//static PSTEntry pst;
//static USTEntry ust;
static WMEApplicationRequest aregreq;
static WMEApplicationRequest awrq;
static WMEApplicationRequest userreq;
static WMEApplicationRequest appreq;
static WMEApplicationRequest pst;
static WMEApplicationRequest ust;
static WMEWRSSRequest wrssrq;
static WMECancelTxRequest canceltxreq;
//stiatic int wbss_status = 0;
//static int appreg_status = 0;
//static char dhost[20];
//static char ssid[255];
//static int wrss = 0;
//static int port = 0;
static int refresh = 0;
static int doNOTrefresh = 0;
//static uint8_t rssi = 0;
int clsock = -1;

//Display Parameters
#define ESC 27
#define HPIPE 205
#define VPIPE 186
#define ULPIPE 201
#define URPIPE 187
#define LLPIPE 200
#define LRPIPE 188
#define REFRESH_DELAY 6000
#define DISPLINES 27
#define DISPCHARS 49
#define MSGWIDTH 8
#define STMSGWIDTH DISPCHARS - 5
enum {
    MAIN, APPREG, WBSS, WSMP, WRSS, GET, SET, PROVIDER, USER, PSID, LOG
};
enum {
    RXPKT, TXPKT, NOTIFIND, WRSSREP, CBJ, ARGS, TSF
};

//static char choice = 0;
static char dispmenu = MAIN;
static char board[DISPLINES][DISPCHARS + 1];
static char status_msg[STMSGWIDTH];
static int devicemode = WAVEDEVICE_LOCAL;
static int status_code;
static int peek;
static unsigned char notifrcvd = 0;
static unsigned char gpsrcvd = 0;
static unsigned char caprcvd = 0;
//static clock_t lastrx;
static struct termios old;
static struct termios newtc;
static int overIP = 0; // 1=UDP, 0=WSMP, 2=IP
//static struct sockaddr_in6 my_addr;

static struct sockaddr_in6 my_addr6;
static struct sockaddr_in my_addr4;

extern const struct in6_addr in6addr_any;
static int desire2join;

struct sockaddr_in6 their_addr;
struct sockaddr_in their_addr_fwd4;
struct sockaddr_in6 their_addr_fwd6;
static int dofwd = 0;
static int sockfd, sockfwd, sockrssi;

static pthread_t capturethread;
//static pthread_t timerthread;
static pthread_t dispthread;
static uint8_t killnow = 0;
static uint8_t reqpending = 0;
static uint8_t logenabled = 0;
static int capture = 0;
//static int listenloggerrunning = 0;
static uint8_t logformat = 0;
static uint16_t listenlogport = 9876;
/*NOTE*/
static struct sockaddr_in6 listenlogip;
static char logfile[512];
static int psid_user = 0;

static uint16_t optport = 0;
static struct sockaddr_in6 optip6;
static struct sockaddr_in optip4;
//static uint8_t portset = 0;
//static int ipset = 0;

void start_capture();

void stop_capture();

void *capture_client(void *data);

void *disp_thread(void *data);
//void *timer(void *data);

void inputhandler(int);

void tx_wsmpkt();

int rx_wsmpkt();

void set_args(void *, char *, int, unsigned int);

void app_registration(int);

void app_request(int);

void wrss_request();

void sig_int(void);

void sig_term(void);

void bye_bye(void);

void receiveWME_NotifIndication(WMENotificationIndication *wmeindication);

void receiveWSMIndication(WSMIndication *wsmindication);

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication);

void receiveTsfTimerIndication(TSFTimer *timer);

int confirmBeforeJoin(WMEApplicationIndication *);

int handler_main(char);

int handler_appreg(char);

int handler_provider(char);

int handler_psid(char);

int handler_user(char);

int handler_wbss(char);

int handler_wsmp(char);

int handler_wrss(char);

int handler_log(char);

void print_board();

void fill_board();

void fill_rxmenu();

void fill_mainmenu();

void fill_appregmenu();

void fill_wbssmenu();

void fill_wsmpmenu();

void fill_wrssmenu();

void fill_getmenu();

void fill_setmenu();

void fill_providermenu();

void fill_usermenu();

void fill_psidmenu();

void fill_logmenu();

int kbhit();

int getch();

int extract_bool(char *);

u_int32_t extract_uint(char *);

int extract_macaddr(u_int8_t *, char *);

int extract_rate(char *);

float index_to_rate(u_int8_t);

//static uint8_t getrssi(int socket, const char* interfacename);

const char *mac_sprintf(const u_int8_t *mac);

void ansi_init();

void clr_status_msg();

extern int parseGPSBinData(GPSData *gps, char *str, int len);

extern int build_gps_wsmpacket(int sockfd, WSMRequest *wsmtxreq, GPSData *gpsdata, GPS_PACKET gpspkt);

void usage() {

    fprintf(stderr, "\nusage:wsmpdemo  [ --remote  targetip | --gps {ip|udp} [ --capture | --forward ]  ]|\n");
    fprintf(stderr, "                [ --ipaddr unicast_ipaddress ] | [ --port udp_port ] |\n");
    fprintf(stderr, "                [ --help print_this_message ]\n\n");
    fprintf(stderr, "                Note: Substitute first charcater of long options for short options.\n\n");
    fprintf(stderr, "                Example: wsmpdemo\n");
    fprintf(stderr, "                Launch wsmpdemo for normal operations on a local machine\n");
    fprintf(stderr, "                Example: wsmpdemo --remote 192.168.1.96\n");
    fprintf(stderr,
            "                Launch wsmpdemo for operations on a target machine with ip address 192.168.1.96\n");
    fprintf(stderr, "                Example: wsmpdemo --gps udp\n");
    fprintf(stderr, "                Launch wsmpdemo to recieve GPS data over UDP\n");
    fprintf(stderr, "                Example: wsmpdemo --gps ip --forward --ip 192.168.1.82 --port 9876\n");
    fprintf(stderr, "                Recieve GPS packets over IP and forward them to 192.168.1.82:9876\n");
    fprintf(stderr, "                Example: wsmpdemo --gps ip --capture --ipaddr 192.168.1.82 --port 9876\n");
    fprintf(stderr, "                Capture GPS packets that are forwarded to 192.168.1.82:9876\n");
    fprintf(stderr,
            "                where 192.168.1.82 is the IP address of one of the interfaces on local machine.\n\n");
    exit(1);
}

void options(int argc, char *argv[]) {
    int index = 0;
    int ret = 0;
    int t;
    int fgps = 0, fremote = 0;
    struct option opts[] =
            {
                    {"help",    no_argument,       0, 'h'},
                    {"capture", no_argument,       0, 'c'},
                    {"forward", no_argument,       0, 'f'},
                    {"remote",  required_argument, 0, 'r'},
                    {"gps",     required_argument, 0, 'g'},
                    {"ipaddr",  required_argument, 0, 'i'},
                    {"port",    required_argument, 0, 'p'},
                    {0,         0,                 0, 0}
            };

    while (1) {
        t = getopt_long(argc, argv, "+hcfr:g:i:p:", opts, &index);
        if (t < 0)
            break;

        switch (t) {

            case 'h':
                usage();
                break;
            case 'c':
                if (fremote) {
                    printf("wsmpdemo: Can't capture in remote mode\n");
                    usage();
                }
                if (dofwd) {
                    printf("wsmpdemo: Can't capture while forwarding\n");
                    usage();
                }
                capture = 1;
                break;

            case 'f':
                if (fremote) {
                    printf("wsmpdemo: Can't forard in remote mode\n");
                    usage();
                }
                if (capture) {
                    printf("wsmpdemo: Can't forward while capturing\n");
                    usage();
                }
                dofwd = 1;
                break;

            case 'r':
                if (fgps || capture || dofwd) {
                    printf("wsmpdemo: remote operation not suported with GPS receive, forward or capture\n");
                    usage();
                }
                devicemode = WAVEDEVICE_REMOTE;
                fremote = 1;
                setRemoteDeviceIP(optarg);
                break;

            case 'g':
                if (fremote) {
                    printf("wsmpdemo: remote operation not suported with GPS receive, forward or capture\n");
                    usage();
                }
                if (!strcasecmp(optarg, "wsmp")) {
                    overIP = 0;
                } else if (!strcasecmp(optarg, "udp")) {
                    overIP = 1;
                } else if (!strcasecmp(optarg, "ip")) {
                    overIP = 2;
                } else {
                    usage();
                }
                fgps = 1;
                break;

            case 'i':
                ret = inet_pton(AF_INET, optarg, &optip4.sin_addr);


                if (ret == 1)
                    ipvfour = 1;

                if (ret != 1) {
                    ret = inet_pton(AF_INET6, optarg, &optip6.sin6_addr);
                    if (ret == 1)
                        ipvfour = 0;
                    if (ret <= 0) {
                        perror("inet_pton() failed");
                    }
                }
                /* else {
					printf("wsmpdemo: Invalid IP address\n");
					usage();
				} */
                break;


            case 'p':
                ret = atoi(optarg);
                if (ret < 1024) {
                    printf("wsmpdemo: Port should be greater than 1024\n");
                    usage();
                }
                optport = (uint16_t) ret;
                break;

            default:
                usage();
        }
    }

}

int main(int argc, char *argv[]) {
    char choice = 0;
    //int i = WAVEDEVICE_LOCAL;
    int change = 0;//, oflags;
//	char str[INET6_ADDRSTRLEN];
    int ret = 0;
    int blockflag = 0;
//	int broadcast = 1;
    int hoplimit = 10;
//	struct ifreq ifr;
//	int sfd, j;
    //struct ifaddrs *ifaddr, *ifa;
//	struct sockaddr_in6 *sin = (struct sockaddr_in6*)&ifr.ifr_addr;

    //struct sockaddr_in *sin4;
    //struct sockaddr_in6 *sin6;
    //struct in6_addr inaddr;

    devicemode = WAVEDEVICE_LOCAL;
    dofwd = 0;
    capture = 0;

    ret = inet_pton(AF_INET, "127.0.0.1", &optip4.sin_addr);

    if (ret != 1) {
        ret = inet_pton(AF_INET6, "::1", &optip6.sin6_addr);
        if (ret != 1)
            perror("inet_pton() failed");
    }

    optport = 9876;
    overIP = 0;
    setRemoteDeviceIP("127.0.0.1");

    ipvfour = 0;


    options(argc, argv);

    switch (overIP) {
        case 0:
            if (dofwd) {
                printf("wsmpdemo: forwarding supported with --gps option only\n");
                usage();
            }
            break;

        case 1:

            if (ipvfour == 1) {
                sockfd = socket(PF_INET, SOCK_DGRAM, 0);

                if (sockfd == -1) {
                    perror("socket");
                    exit(1);
                }

                /* if (setsockopt(sockfd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
				sizeof(hoplimit)) == -1) {
					perror("setsockopt (IPV6_UNICAST_HOPS)");
					exit(-1);
				} */

                my_addr4.sin_family = AF_INET;
                my_addr4.sin_port = htons(MYPORT);
                my_addr4.sin_addr.s_addr = INADDR_ANY;

                if (bind(sockfd, (struct sockaddr *) &my_addr4,
                         sizeof(struct sockaddr)) == -1) {
                    perror("bind what");
                    close(sockfd);
                    exit(1);
                }
            }
            else if (ipvfour == 0) {
                sockfd = socket(PF_INET6, SOCK_DGRAM, 0);

                if (sockfd == -1) {
                    perror("socket");
                    exit(1);
                }

                if (setsockopt(sockfd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
                               sizeof(hoplimit)) == -1) {
                    perror("setsockopt (IPV6_UNICAST_HOPS)");
                    exit(-1);
                }

                my_addr6.sin6_family = AF_INET6;
                my_addr6.sin6_port = htons(MYPORT);

                memcpy((void *) &my_addr6.sin6_addr, (void *) &in6addr_any, 17);

                if (bind(sockfd, (struct sockaddr *) &my_addr6,
                         sizeof(struct sockaddr_in6)) == -1) {
                    perror("bind what");
                    close(sockfd);
                    exit(1);
                }

            }

            /* sockfd = socket(PF_INET6, SOCK_DGRAM, 0);
			fcntl(sockfd, F_SETFL, O_NONBLOCK);
			if (sockfd  == -1) {
				perror("socket");
				exit(1);
			}
			if (setsockopt(sockfd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
				sizeof(hoplimit)) == -1) {
				perror("setsockopt (IPV6_UNICAST_HOPS)");
				exit(-1);
			}
			my_addr.sin6_family = AF_INET6;
			my_addr.sin6_port = htons(MYPORT);
			my_addr.sin6_addr = in6addr_any;
			//memset(&(my_addr.sin_zero), '\0', 8);

			if (bind(sockfd, (struct sockaddr *)&my_addr,
				sizeof(struct sockaddr)) == -1) {
				perror("bind what");
				close(sockfd);
				exit(1);
			} */

            break;

        case 2:

            if (ipvfour == 1) {
                sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                fcntl(sockfd, F_SETFL, O_NONBLOCK);
                if (sockfd == -1) {
                    perror("wsmpdemo: socket");
                    exit(1);
                }
                if (setsockopt(sockfd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
                               sizeof(hoplimit)) == -1) {
                    perror("wsmpdemo: setsockopt (IPV6_UNICAST_HOPS)");
                    exit(1);
                }

            }
            else if (ipvfour == 0) {
                sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
                fcntl(sockfd, F_SETFL, O_NONBLOCK);
                if (sockfd == -1) {
                    perror("wsmpdemo: socket");
                    exit(1);
                }
                if (setsockopt(sockfd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
                               sizeof(hoplimit)) == -1) {
                    perror("wsmpdemo: setsockopt (IPV6_UNICAST_HOPS)");
                    exit(1);
                }
            }
            break;

        default:
            printf("wsmpdemo: Unexpected mode\n");
            usage();
    }

    if (capture) {
        //listenlogip = optip;
        memcpy(&listenlogip.sin6_addr, &optip6.sin6_addr, sizeof(struct in6_addr));
        listenlogport = optport;
        start_capture();
    }
    if (dofwd) {
        if (ipvfour == 1) {
            if ((sockfwd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                perror("socket");
                exit(-1);
            }
            /* if (setsockopt(sockfwd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
			sizeof(hoplimit)) == -1) {
			perror("setsockopt (IPV6_UNICAST_HOPS)");
			exit(-1);
		} */
            their_addr_fwd4.sin_family = AF_INET;
            their_addr_fwd4.sin_port = htons(optport);
            their_addr_fwd4.sin_addr.s_addr = optip4.sin_addr.s_addr;
        }
        else if (ipvfour == 0) {
            if ((sockfwd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
                perror("socket");
                exit(-1);
            }
            if (setsockopt(sockfwd, SOL_SOCKET, IPV6_UNICAST_HOPS, &hoplimit,
                           sizeof(hoplimit)) == -1) {
                perror("setsockopt (IPV6_UNICAST_HOPS)");
                exit(-1);
            }
            their_addr_fwd6.sin6_family = AF_INET6;
            their_addr_fwd6.sin6_port = htons(optport);
            their_addr_fwd6.sin6_addr = in6addr_any;

        }
    }

    sockrssi = socket(AF_INET6, SOCK_STREAM, 0);// dummy socket for rssi fetch

    getUSTIpv6Addr(&userreq.ipv6addr, "eth0");
    aregreq.ipv6addr = userreq.ipv6addr;
    pst.ipv6addr = userreq.ipv6addr;
    if (!capture)listenlogip.sin6_addr = userreq.ipv6addr;

#if 0
                                                                                                                            sfd = socket(AF_INET6, SOCK_STREAM, 0);
	if(sfd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		/*if no TARGETIP is provided set default ip addresses to lo*/
		strcpy(ifr.ifr_name, ((devicemode == WAVEDEVICE_REMOTE) && (argv[2] == NULL) )? "lo" : "eth0");
		sin->sin6_family = AF_INET6;
		if(ioctl(sfd, SIOCGIFADDR, &ifr) == 0) {
            aregreq.ipv6addr = sin->sin6_addr;
			pst.ipv6addr = sin->sin6_addr;
			ust.ipv6addr = sin->sin6_addr;
			if(!capture)listenlogip.sin6_addr = sin->sin6_addr;
		}
		else {
  			inet_pton(AF_INET, "127.0.0.1", &aregreq.ipv6addr);
			inet_pton(AF_INET, "127.0.0.1", &pst.ipv6addr);
			inet_pton(AF_INET, "127.0.0.1", &ust.ipv6addr);
			if(!capture)inet_pton(AF_INET, "127.0.0.1", &listenlogip.sin6_addr);

/*  			inet_pton(AF_INET6, "::1", &aregreq.ipv6addr);
			inet_pton(AF_INET6, "::1", &pst.ipv6addr);
			inet_pton(AF_INET6, "::1", &ust.ipv6addr);
			if(!capture)inet_pton(AF_INET6, "::1", &listenlogip.sin6_addr);
*/
		}
	}

#endif
    memset(&wsmtxreq, 0, sizeof(WSMRequest));
    memset(&wsmrxind, 0, sizeof(WSMIndication));

    if ((overIP == 0) && (invokeWAVEDevice(devicemode, blockflag) < 0)) {
        printf("wsmpdemo: Open Failed, Module not loaded or Device file does not exist \n");
        return -1;
    }

    registerWMENotifIndication(receiveWME_NotifIndication);
    registerWSMIndication(receiveWSMIndication);
    registerWRSSIndication(receiveWRSS_Indication);
    registertsfIndication(receiveTsfTimerIndication);
    registerLinkConfirm(confirmBeforeJoin);

    if (devicemode == WAVEDEVICE_REMOTE) {
        aregreq.notif_port = 6666;
        ust.serviceport = 8888;
        userreq.serviceport = 8888;
        appreq.serviceport = 8888;
        setWMEApplRegNotifParams(&aregreq);
    } else {
        aregreq.notif_port = 0;
        userreq.serviceport = 0;

        appreq.serviceport = 0;
        aregreq.ipv6addr.s6_addr32[0] = 0;
        pst.ipv6addr.s6_addr32[0] = 0;
        ust.ipv6addr.s6_addr32[0] = 0;
    }

    if (!capture)memset(&listenlogport, 0, sizeof(uint16_t));
    sprintf(logfile, "%s", DEFAULT_LOGFILE);
    set_logfile(logfile);
    //set_logging_addr(listenlogip, 9876);
    set_logging_mode(0);

    ansi_init();
    print_board();
    pid = getpid();

    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);

    pthread_create(&dispthread, NULL, disp_thread, NULL); // To refresh the display after every one second

    do {

        choice = '$';

        if (kbhit()) {
            choice = tolower(getch());
        }

        change = 1;
        switch (dispmenu) {
            case MAIN:
                change = handler_main(choice);
                break;

            case APPREG:
                change = handler_appreg(choice);
                break;

            case WBSS:
                change = handler_wbss(choice);
                break;

            case WSMP:
                change = handler_wsmp(choice);
                break;

            case WRSS:
                change = handler_wrss(choice);
                break;

            case GET:
                change = 0;
                break;

            case SET:
                change = 0;
                break;

            case LOG:
                change = handler_log(choice);
                break;

            case PROVIDER:
                change = handler_provider(choice);
                break;

            case USER:
                change = handler_user(choice);
                break;

            case PSID:
                change = handler_psid(choice);
                break;

            default:
                change = 0;
        }
        ret = rx_wsmpkt();

        if (change)
            print_board();

    } while (choice != 'q');
    close(sockfd);
    bye_bye();
    return 0;
}

void start_capture() {
    pthread_create(&capturethread, NULL, capture_client, NULL);
}


void stop_capture() {
    pthread_cancel(capture_client);
    close(clsock);
}

void *capture_client(void *data) {
    int len, lenfrom;
    //uint16_t port;
    unsigned char buf[1024];
    struct sockaddr_in6 client;
    struct sockaddr_in6 from;

    clsock = socket(AF_INET6, SOCK_DGRAM, 0);

    if (clsock < 0)
        perror("SOCK");

    client.sin6_family = AF_INET6;
    client.sin6_addr = listenlogip.sin6_addr;
    client.sin6_port = htons(listenlogport);
    len = lenfrom = sizeof(struct sockaddr_in6);

    if (bind(clsock, (struct sockaddr *) &client, len) < 0)
        return NULL;

    lenfrom = sizeof(struct sockaddr_in6);
    while (1) {
        len = recvfrom(clsock, buf, 1024, 0, (struct sockaddr *) &from, &lenfrom);
        memcpy(&addwsmp.packetnum, buf, 4);
        memcpy(&addwsmp.rssi, buf + 4, 1);
        memcpy(addwsmp.macaddr, buf + 5, 6);
        memcpy(wsmrxind.data.contents, buf + 11, len - 11);
        wsmrxind.data.length = len - 11;
        parseGPSBinData(&rxgpsdata, wsmrxind.data.contents, wsmrxind.data.length);
        if (capture) {
            numrx++;
            sizerx += len;
            sprintf(status_msg, "GPS(Captured) Received(%u Bytes)", len);
            caprcvd = 1;
            gpsrcvd = 1;
            print_board();
            gpsrcvd = 0;
            caprcvd = 0;
        }
    }
}


void tx_wsmpkt() {
    int ret = 0;//, i =0;
    u_int16_t size = 0, attempts = 0, numd = 0;//, percent = 0;

    if (txrepeat < 1) txrepeat = (u_int16_t) 1;

    if (wsmtxreq.data.length < 1) {
        wsmtxreq.data.length = 0;
        /*strncpy(wsmtxreq.data.contents, DEFAULT_WSM, wsmtxreq.data.length);*/
    }


    clr_status_msg();
    sprintf(status_msg, "Transmiting %d WSM Packets. Please WAIT...", txrepeat);
    print_board();

    for (attempts = 0; attempts < txrepeat; attempts++) {
        size = sizeof(struct channelInfo) +
               4 + 8 + wsmtxreq.data.length;
        ret = txWSMPacket(pid, &wsmtxreq);
        if (ret < 0) {
            numdropped++;
            numd++;
            if (ret == -EAGAIN) {
                clr_status_msg();
                sprintf(status_msg,
                        "WSMP buffer unavailable");
                print_board();
                return;
            } else if (ret < 0) {
                clr_status_msg();
                sprintf(status_msg,
                        "PSID is Not a Provider,Packet Dropped");
            }
        } else {
            numtx++;
            sizetx = (u_int32_t)(sizetx + size);
        }
        ret = 0;
        usleep(txdelay);
    }

    clr_status_msg();
    sprintf(status_msg, "%u, %u Byte WSM Packets Transmited", (u_int32_t)(txrepeat - numd), (u_int32_t) size);
    status_code = TXPKT;
    size = 0;
}


int
AsmDecodeContentType(WSMIndication *rxpkt) {
    int version, Content_type = 0, offset = 0;
    version = rxpkt->data.contents[offset];
    if (version == 2) {
        offset++;
        Content_type = rxpkt->data.contents[offset];
        return Content_type;
    }
    return Content_type;
}

int rx_wsmpkt() {
    int ret = 0;//, i = 0;
    int cmp;
    int len;//count
//	struct ip *iph;
//	socklen_t addr_len;
    struct FullPositionVector *fpv;
    WSMData data;
    void *Logdata;
    uint16_t status;
    uint32_t temp_var;
    BasicSafetyMessage_t *bsmLog;

    int numbytes = 0, nb = 0;
    static unsigned char buf[MAXBUFLEN];
    static unsigned char logbuf[MAXBUFLEN];
    uint16_t tempbuf, Content_type;
    unsigned char *p;
    int ret_val;
    p = &tempbuf;

    if (devicemode == WAVEDEVICE_LOCAL) {
    }


    if (overIP == 1) {
        if ((numbytes = read(sockfd, buf, MAXBUFLEN - 1)) == -1) {
            return -1;
        }
        memcpy(rxpkt.data.contents, buf, numbytes);
        memcpy(&addwsmp.packetnum, rxpkt.data.contents, 4);
        memcpy(&addwsmp.rssi, rxpkt.data.contents + 4, 1);
        memcpy(addwsmp.macaddr, rxpkt.data.contents + 5, 6);
        rxpkt.data.length = numbytes;
        if (dofwd) {

            if (ipvfour == 1) {
                if ((nb = sendto(sockfwd,
                                 buf,
                                 numbytes,
                                 0,
                                 (struct sockaddr *) &their_addr_fwd4,
                                 sizeof(their_addr_fwd4))) == -1) {
                    perror("sendto");
                    exit(-1);
                } else {
                    //printf("UDP GPS data forwarded \n");
                }
            }
            else if (ipvfour == 0) {
                if ((nb = sendto(sockfwd,
                                 buf,
                                 numbytes,
                                 0,
                                 (struct sockaddr *) &their_addr_fwd6,
                                 sizeof(their_addr_fwd6))) == -1) {
                    perror("sendto");
                    exit(-1);
                } else {
                    //printf("UDP GPS data forwarded \n");
                }

            }

        }
    } else if (overIP == 2) {
        numbytes = read(sockfd, buf, 1000);
        if (numbytes < 0)
            return -1;
        memcpy(rxpkt.data.contents, buf + 20, numbytes - 20);
        memcpy(&addwsmp.packetnum, rxpkt.data.contents, 4);
        memcpy(&addwsmp.rssi, rxpkt.data.contents + 4, 1);
        memcpy(addwsmp.macaddr, rxpkt.data.contents + 5, 6);
        rxpkt.data.length = numbytes - 20;
        if (dofwd) {
            if (ipvfour == 1) {
                if ((nb = sendto(sockfwd,
                                 buf + 20,
                                 numbytes - 20,
                                 0,
                                 (struct sockaddr *) &their_addr_fwd4,
                                 sizeof(struct sockaddr))) == -1) {
                    perror("sendto");
                    exit(-1);
                } else {
                    //printf("IP GPS data forwarded \n");
                }
            }
            else if (overIP == 0) {
                if ((nb = sendto(sockfwd,
                                 buf + 20,
                                 numbytes - 20,
                                 0,
                                 (struct sockaddr *) &their_addr_fwd6,
                                 sizeof(struct sockaddr))) == -1) {
                    perror("sendto");
                    exit(-1);
                } else {
                    //printf("IP GPS data forwarded \n");
                }
            }
        }
    } else if (overIP == 0) {
        ret = -1;
        if (devicemode == WAVEDEVICE_LOCAL)
            ret = rxWSMPacket(pid, &rxpkt);
        if (ret < 0) {
            return ret;
        } else {
            refresh = 1;
        }
    }

    numrx++;
    sizerx = (u_int64_t)(sizerx + 4 + 8 + rxpkt.data.length);
/*TODO*/
#if 1

    if ((rxpkt.psid == 9) || (overIP > 0)) {
        gpsrcvd = 1;
    }
#endif
    if (gpsrcvd) {
        ret = -1;
        if (rxpkt.data.length > 11) {
            memcpy(&addwsmp.packetnum, rxpkt.data.contents, 4);
            memcpy(&addwsmp.rssi, rxpkt.data.contents + 4, 1);
            memcpy(addwsmp.macaddr, rxpkt.data.contents + 5, 6);
            ret = parseGPSBinData(&rxgpsdata, rxpkt.data.contents + 11, rxpkt.data.length - 11);
            if (logenabled) {
                len = build_gps_logentry(0, logbuf, &rxpkt, &addwsmp, &rxgpsdata, get_gps_contents());
                //len = build_gps_xmlentry(0, logbuf, &rxpkt, &addwsmp, &rxgpsdata, get_gps_contents());
                if (len > 0)write_logentry(logbuf, len);
            }
        }
        if (ret < 0) gpsrcvd = 0;
        if (overIP > 0) goto outrx;
    }
    else {
        if ((rxpkt.psid != 9) && (rxpkt.data.contents[0] == 48)) {
            Content_type = AsmDecodeContentType(&rxpkt);
            rxmsg.wsmIndication = &rxpkt;
            rxWSMIdentity(&rxmsg, Content_type);
            if (!rxmsg.decode_status) if (rxmsg.type == WSMMSG_BSM) {
                valid_bsm = 1;
                bsmLog = (BasicSafetyMessage_t *) rxmsg.structure;
                memcpy(&latitude_val, bsmLog->blob1.buf + 7, 4);
                temp_var = htobe32(latitude_val);
                latitude_val = temp_var;
                memcpy(&longitude_val, bsmLog->blob1.buf + 11, 4);
                temp_var = longitude_val;
                longitude_val = htobe32(temp_var);
                memcpy(&altitude_val, bsmLog->blob1.buf + 15, 2);
                memcpy(&speed_val, bsmLog->blob1.buf + 21, 2);
                memcpy(&heading_val, bsmLog->blob1.buf + 23, 2);
                if (bsmLog->status != NULL) {
                    Logdata = (void *) (bsmLog->status->fullPos);
                    fpv = (struct FullPositionVector *) Logdata;
                    year_val = *(fpv->utcTime->year);
                    month_val = *(fpv->utcTime->month);
                    day_val = *(fpv->utcTime->day);
                }
                ret = 1;

            }
            else { }
            if (logenabled) {
                Logdata = (void *) bsmLog;
                len = AsnLog(0, 0, rxmsg.type, logformat, logbuf_t, Logdata, &rxpkt, 0, 0);
                //if(len > 0)write_logentry(logbuf_t, len);
            } //logenabled

        }//psid
        else {
            if (logenabled && (overIP == 0)) {
                len = build_gps_logentry(0, logbuf, &rxpkt, NULL, NULL, 0);
                //len = build_gps_xmlentry(0, logbuf, &rxpkt, NULL, NULL, 0);
                if (len > 0)write_logentry(logbuf, len);
            }    //if
        }//else

    }

    cmp = (rxpkt.chaninfo.channel == wsmrxind.chaninfo.channel) && (rxpkt.chaninfo.txpower == wsmrxind.chaninfo.txpower)
          && (rxpkt.psid == wsmrxind.psid) && (rxpkt.version == wsmrxind.version) &&
          (rxpkt.security == wsmrxind.security)
          && (rxpkt.txpriority == wsmrxind.txpriority)
          && (rxpkt.data.length == wsmrxind.data.length)
          && (!memcmp(rxpkt.data.contents, wsmrxind.data.contents, rxpkt.data.length));
    outrx:

    memcpy(&wsmrxind, &rxpkt, sizeof(WSMIndication));


    clr_status_msg();
    if (overIP == 0)
        sprintf(status_msg, "%s(WSM) Received (%u Bytes)", (gpsrcvd) ? " GPS" : " ", 9 + rxpkt.data.length);
    if (overIP == 1) sprintf(status_msg, "GPS(UDP) Received (%u Bytes)", rxpkt.data.length);
    if (overIP == 2) sprintf(status_msg, "GPS(IP) Received (%u Bytes)", sizeof(struct ip) + rxpkt.data.length);
    status_code = RXPKT;

    if (!cmp || overIP > 0) {
        refresh = 1;
        //print_board();
    }

    return 1;
}

void set_args(void *data, char *argname, int datatype, unsigned int maxlimit) {
    int i = 0;
    int ch;
    char change = ' ';
    u_int8_t string[1000];
    u_int32_t temp = 0;
    u_int8_t temp8 = 0;
    u_int16_t temp16 = 0;
    u_int32_t temp32 = 0;
    u_int64_t temp64 = 0;

    doNOTrefresh = 1;
    if (data == NULL)
        return;
    if (argname == NULL)
        return;

    clr_status_msg();

    switch (datatype) {
        case BOOL:
            printf("\b[%s=%u] Change (y/n)?:", argname, *(u_int8_t *) data);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enterbool:
                printf("\n New Value[0/1]:");
                fgets(string, OCTET_MAX_LENGTH, stdin);
                {
                    unsigned int last = strlen(string) - 1;
                    if (string[last] == '\n') string[last] = '\0';
                }
                temp8 = (uint8_t) extract_bool(string);
                if ((temp8 > 1)) {
                    printf("\n Invalid Value- Appended Spaces or Value out of Bounds");
                    goto enterbool;
                }
                memcpy(data, &temp8, sizeof(u_int8_t));
            }
            doNOTrefresh = 0;
            break;

        case UINT8:
            printf("\b[%s=%u] Change (y/n)?:", argname, *(u_int8_t *) data);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enteruint8:
                printf("\n New Value[0,%u]:", maxlimit);
                fgets(string, OCTET_MAX_LENGTH, stdin);
                {
                    unsigned int last = strlen(string) - 1;
                    if (string[last] == '\n') string[last] = '\0';
                }
                temp = extract_uint(string);
                if ((temp < 0) || (temp > maxlimit)) {
                    printf("\n Invalid Value- Appended Spaces or Value out of Bounds");
                    goto enteruint8;
                }
                temp8 = (u_int8_t) temp;
                memcpy(data, &temp8, sizeof(u_int8_t));
            }
            doNOTrefresh = 0;
            break;

        case UINT16:
            printf("\b[%s=%u] Change (y/n)?:", argname, *(u_int16_t *) data);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enteruint16:
                printf("\nNew Value[0,%u]:", maxlimit);
                fgets(string, OCTET_MAX_LENGTH, stdin);
                {
                    unsigned int last = strlen(string) - 1;
                    if (string[last] == '\n') string[last] = '\0';
                }
                temp = extract_uint(string);
                if ((temp < 0) || (temp > maxlimit)) {
                    printf("\n Invalid Value- Appended Spaces or Value out of Bounds");
                    goto enteruint16;
                }
                temp16 = (u_int16_t) temp;
                memcpy(data, &temp16, sizeof(u_int16_t));
            }
            doNOTrefresh = 0;
            break;

        case UINT32:
            printf("\b[%s=%u] Change (y/n)?:", argname, *(u_int32_t *) data);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enteruint32:
                printf("\nNew Value[0,%u]:", maxlimit);
                fgets(string, OCTET_MAX_LENGTH, stdin);
                {
                    unsigned int last = strlen(string) - 1;
                    if (string[last] == '\n') string[last] = '\0';
                }
                temp = extract_uint(string);
                if ((temp < 0) || (temp > maxlimit)) {
                    printf("\n Invalid Value- Appended Spaces or Value out of Bounds");
                    goto enteruint32;
                }
                temp32 = (u_int32_t) temp;
                memcpy(data, &temp32, sizeof(u_int32_t));
            }
            doNOTrefresh = 0;
            break;

        case UINT64:
            printf("\b[%s=%llu] Change (y/n)?:", argname, *(u_int64_t *) data);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enteruint64:
                printf("\nNew Value[0,%u]:", maxlimit);
                fgets(string, OCTET_MAX_LENGTH, stdin);
                {
                    unsigned int last = strlen(string) - 1;
                    if (string[last] == '\n') string[last] = '\0';
                }
                temp = extract_uint(string);
                if ((temp < 0) || (temp > maxlimit)) {
                    printf("\n Invalid Value- Appended Spaces or Value out of Bounds");
                    goto enteruint64;
                }
                temp64 = (u_int64_t) temp;
                memcpy(data, &temp64, sizeof(u_int64_t));
            }
            doNOTrefresh = 0;
            break;

        case STRING:
            memset(string, 0, 1000);
            strncpy(string, data, strlen(data));
            printf("\b[%s=%s] Change (y/n)?:", argname, string);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                printf("\nNew Value[String, MaxLen=%d]:", OCTET_MAX_LENGTH);
                i = 0;
                while ((ch = getchar()) != '\n' && ch != EOF) {
                    if (i < OCTET_MAX_LENGTH) string[i++] = (char) ch;
                }
                if (i < OCTET_MAX_LENGTH - 1)
                    string[i] = '\0';
                else
                    string[OCTET_MAX_LENGTH - 1] = '\0';

                memcpy(data, string, OCTET_MAX_LENGTH);
            }
            doNOTrefresh = 0;
            break;

        case STRINGLONG:
            memset(string, 0, 1000);
            strncpy(string, data, strlen(data));
            printf("\b[%s=%s] Change (y/n)?:", argname, string);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                printf("\nNew Value[String, MaxLen=%d]:", HALFK);
                i = 0;
                while ((ch = getchar()) != '\n' && ch != EOF) {
                    if (i < HALFK) string[i++] = (char) ch;
                }
                if (i < HALFK - 1)
                    string[i] = '\0';
                else
                    string[HALFK - 1] = '\0';

                memcpy(data, string, HALFK);
            }
            doNOTrefresh = 0;
            break;

        case ADDR_MAC:
            memcpy(string, data, IEEE80211_ADDR_LEN);
            printf("\b[%s=", argname);
            for (i = 0; i < IEEE80211_ADDR_LEN; i++)
                printf("%2X:", string[i]);
            printf("\b] Change (y/n)?:");
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                entermac:
                printf("\nNew Value[HEX _:_:_:_:_:_]:");
                scanf("%s", string);
                if (extract_macaddr(data, string) < 0) {
                    printf("\nInvalid Value");
                    goto entermac;
                }

            }
            doNOTrefresh = 0;
            break;

        case ADDR_IPV4:
            memset(string, 0, 1000);
            printf("\b[%s] Change (y/n)?:", argname);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enterip:
                printf("\nNew Value[IP Address]:");
                i = 0;
                while ((ch = getchar()) != '\n' && ch != EOF) {
                    if (i < OCTET_MAX_LENGTH) string[i++] = (char) ch;
                }
                if (i < OCTET_MAX_LENGTH - 1)
                    string[i] = '\0';
                else
                    string[OCTET_MAX_LENGTH - 1] = '\0';

                temp = inet_pton(AF_INET, string, (struct in6_addr *) data);
                if (temp < 0) {
                    printf("\nInvalid Value");
                    goto enterip;
                }

            }
            doNOTrefresh = 0;
            break;

        case ADDR_IPV6:
            memset(string, 0, 1000);
            printf("\b[%s] Change (y/n)?:", argname);
            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                //enteripv6:
                while ((ch = getchar()) != '\n' && ch != EOF) {
                    if (i < 128) string[i++] = (char) ch;
                }
                if (i < (128 - 1))
                    string[i] = '\0';
                else
                    string[128 - 1] = '\0';

                temp = inet_pton(AF_INET6, string, (struct in6_addr *) data);
                if (temp < 0) {
                    printf("\nInvalid Value");
                    goto enterip;
                }
            }
            doNOTrefresh = 0;
            break;

        case RATESET:

            if (index_to_rate(*(u_int8_t *) data) < 0.0f) {
                printf("\b%s NOT SET! Change (y/n)?:", argname);
            } else {
                printf("\b[%s=%3.1f] Change (y/n)?:", argname,
                       index_to_rate(*(u_int8_t *) data));
            }

            fflush(stdout);
            while (!kbhit());
            change = getch();
            if ('y' == tolower(change)) {
                enterrate:
                printf("\nNew Value[");
                for (i = 1; i < RATESET_NUM_ELMS; i++)
                    printf("%3.1f/", rate_set[i]);
                printf("\b]:");
                scanf("%s", string);
                temp = extract_rate(string);
                if (temp < 0) {
                    printf("\n Invalid Value");
                    goto enterrate;
                }
                temp8 = (u_int8_t) temp;
                memcpy(data, &temp8, sizeof(u_int8_t));
            }
            doNOTrefresh = 0;
            break;

    }
    sprintf(status_msg, "%s %s", argname, ('y' == tolower(change)) ? "Modified" : "Viewed");
    status_code = ARGS;
}

void app_registration(int action) {
    int result;
//	int length;
    int add = 0;
//	WAVEHandler waveRequest;
//	WMEApplicationRequest appRegRequest;
    clr_status_msg();

    switch (action) {
        case WME_ADD_PROVIDER:
            tareq.action = TA_ADD;
            tareq.repeatrate = 100;
            tareq.channel = 178;
            tareq.channelinterval = 1;
            tareq.servicepriority = 1;
            appreq.channelaccess = CHACCESS_ALTERNATIVE;


            result = registerProvider(pid, &appreq);
            printf("starting TA\n");
            if (transmitTA(&tareq) < 0) {
                printf("send TA failed\n ");
            } else {
                printf("send TA successful\n");
            }
            add = 1;
        case WME_DEL_PROVIDER:

            if (add == 0) {
                result = removeProvider(pid, &appreq);
            }
            sprintf(status_msg, "Provider %sRegistration %s", (add == 1) ? " " : "Un",
                    (result < 0) ? "Failed" : "Successful");

            break;

        case WME_ADD_USER:
            if (!usrReqFlag)
                userreq.userreqtype = USER_REQ_SCH_ACCESS_AUTO;
            result = registerUser(pid, &userreq);
            add = 1;
        case WME_DEL_USER:

            if (add == 0) {
                result = removeUser(pid, &userreq);
            }
            sprintf(status_msg, "User %sRegistration %s", (add == 1) ? " " : "Un",
                    (result < 0) ? "Failed" : "Successful");

            break;

    }


}

void app_request(int reqtype) {
    int result;

    clr_status_msg();

    switch (reqtype) {

        case APP_ACTIVE:
            result = startWBSS(pid, &awrq);
            sprintf(status_msg, "WBSS Start request %s", (result < 0) ? "Failed" : "Successful");
            break;
        case APP_INACTIVE:
            result = stopWBSS(pid, &awrq);
            sprintf(status_msg, "WBSS Stop request %s", (result < 0) ? "Failed" : "Successful");
            break;
        case APP_UNAVAILABLE:
            result = makeUnavailableWBSS(pid, &awrq);
            sprintf(status_msg, "WBSS Unavailable request %s", (result < 0) ? "Failed" : "Successful");
            break;

    }


}


void wrss_request() {
    int result;

    result = getWRSSReport(pid, &wrssrq);
    if (result < 0) {
        clr_status_msg();
        sprintf(status_msg, "WRSS Request Failed");
        print_board();
    }
}

void receiveWME_NotifIndication(WMENotificationIndication *wmeindication) {
    static int count = 0;
    count++;
    notifrcvd = 1;
    clr_status_msg();
    sprintf(status_msg, "WME Notification-Indication Received %d", count);
    if (count % 20 == 0) refresh = 1;
    status_code = NOTIFIND;
}


void receiveWSMIndication(WSMIndication *wsmindication) {
    static int count = 0;
    int ret = 0;
    int len = 0;
    static char logbuf[MAXBUFLEN];

    count++;
    numrx++;
    sizerx = (u_int64_t)(sizerx + 9 + wsmindication->data.length);

    clr_status_msg();
    sprintf(status_msg, "WSM Indication Received %d", count);
    memcpy(&wsmrxind, wsmindication, sizeof(WSMIndication));
    if ((wsmrxind.psid == 9)) {
        gpsrcvd = 1;
        clr_status_msg();
        sprintf(status_msg, "GPS(WSM) Indication Received %d", count);
        refresh = 1;
        //print_board();
    }
    if (gpsrcvd) {
        ret = -1;
        if (wsmrxind.data.length > 11) {
            memcpy(&addwsmp.packetnum, wsmrxind.data.contents, 4);
            memcpy(&addwsmp.rssi, wsmrxind.data.contents + 4, 1);
            memcpy(addwsmp.macaddr, wsmrxind.data.contents + 5, 6);
            ret = parseGPSBinData(&rxgpsdata, wsmrxind.data.contents + 11, wsmrxind.data.length - 11);
            if (logenabled) {
                len = build_gps_logentry(0, logbuf, &wsmrxind, &addwsmp, &rxgpsdata, get_gps_contents());
                //len = build_gps_xmlentry(0, logbuf, &wsmrxind, &addwsmp, &rxgpsdata, get_gps_contents());
                if (len > 0)write_logentry(logbuf, len);
            }
        }
        if (ret < 0) gpsrcvd = 0;
    } else {
        if (logenabled) {
            len = build_gps_logentry(0, logbuf, &wsmrxind, NULL, NULL, 0);
            //len = build_gps_xmlentry(0, logbuf, &wsmrxind, NULL, NULL, 0);
            if (len > 0)write_logentry(logbuf, len);
        }
    }
    if (count % 100 == 0)
        print_board();

}

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication) {
    notifrcvd = 1;
    clr_status_msg();
    sprintf(status_msg, "Report Recieved: Chan=%d, WRSS=%d", (u_int8_t) wrssindication->wrssreport.channel,
            (u_int8_t) wrssindication->wrssreport.wrss);
    status_code = WRSSREP;
    print_board();

}

void receiveTsfTimerIndication(TSFTimer *timer) {
    notifrcvd = 1;
    clr_status_msg();
    sprintf(status_msg, "TSF Timer: Result=%d, Timer=%llu", (u_int8_t) timer->result, (u_int64_t) timer->timer);
    status_code = TSF;
    print_board();
}

int confirmBeforeJoin(WMEApplicationIndication *appind) {
    clr_status_msg();
    //sprintf(status_msg, "Link Confirmed SrvcIP=%s", inet_ntoa(htons(appind->ipaddr)));
    sprintf(status_msg, "Joining  status 1/0 (join/not join) %d", desire2join);
    status_code = CBJ;
    refresh = 0;
    return desire2join; /*Return 1 to Join WBSS anirban   */
}


//***********************Menu Handlers*****************************************

int handler_main(char choice) {
    int change = 1;

    switch (choice) {

        case 'a':
            dispmenu = APPREG;
            break;

        case 'b':
            dispmenu = WBSS;
            break;

        case 'w':
            dispmenu = WSMP;
            break;

        case 'r':
            dispmenu = WRSS;
            break;

        case 't':
            clr_status_msg();
            sprintf(status_msg, "TSF Timer = %llu", (u_int64_t) getTsfTimer(pid));
            print_board();
            break;


        case 'i':
            set_args(&canceltxreq.aci, "Cancel TX ACI", UINT8, 3);
            break;

        case 'c':
            set_args(&canceltxreq.channel, "Cancel TX Channel", UINT8, UINT8MAX);
            break;

        case 'e':
            clr_status_msg();
            sprintf(status_msg, "Cancel TX %s", (cancelTX(pid, &canceltxreq) > -1) ? "Succesful" : "Failed");
            print_board();
            break;


        case 'l':
            dispmenu = LOG;
            break;

        case 'g':
            dispmenu = MAIN;
            break;

        case 's':
            dispmenu = MAIN;
            break;

        case '/':
            dispmenu = MAIN;
            break;

        default:
            change = 0;
    }
    return change;

}

int handler_appreg(char choice) {
    int change = 1;

    switch (choice) {

        case 'p':
            dispmenu = PROVIDER;
            break;

        case 'u':
            dispmenu = USER;
            break;

        case 'i':
            set_args(&aregreq.ipv6addr, "APP WME Notification IP", ADDR_IPV6, 0);
            setWMEApplRegNotifParams(&aregreq);
            break;

        case 'o':
            set_args(&aregreq.notif_port, "APP WME Notification Port", UINT16, UINT16MAX);
            setWMEApplRegNotifParams(&aregreq);
            break;

        case ESC:
            dispmenu = MAIN;
            break;
        default:
            change = 0;
    }

    return change;
}

int handler_psid(char choice) {
    int change = 1;
//	int psid = 0,n;
    switch (choice) {


        case 't':

            if (wsmp_psid == 1) {
                set_args(&wsmtxreq.psid,
                         "WSMP ACM", UINT32,
                         UINT32MAX);
                if (wsmtxreq.psid == 1) {
                    wsmtxreq.psid = 5;
                }
                break;
            }
            if (wbss_psid == 1) {
                set_args(&awrq.psid, "WBSS ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 5;
                break;
            }
            if (psid_user) {
                set_args(&userreq.psid, "ENTER 'y' THEN 1 FOR TRAFIC CONTROL", UINT32, UINT32MAX);
                if (userreq.psid == 1)
                    userreq.psid = 5;
            }
            else {
                set_args(&appreq.psid, "ENTER 'y' THEN 1 FOR TRAFIC CONTROL", UINT32, UINT32MAX);
                if (appreq.psid == 1)
                    appreq.psid = 5;
            }
            break;

        case 'p':
            if (wsmp_psid == 1) {
                set_args(&wsmtxreq.psid,
                         "WSMP ACM", UINT32,
                         UINT32MAX);
                if (wsmtxreq.psid == 1) {
                    wsmtxreq.psid = 13;
                }
                break;
            }
            if (wsmp_psid == 1) {
//				set_args(&wsmtxreq.psid, "WSMP ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 13;
                break;
            }
            if (wbss_psid == 1) {
                set_args(&awrq.psid, "WBSS ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 13;
                break;
            }
            if (psid_user) {
                set_args(&userreq.psid, "ENTER 'y' THEN 1 FOR PRIVATE", UINT32, UINT32MAX);
                if (userreq.psid == 1)
                    userreq.psid = 13;
            }
            else {
                set_args(&appreq.psid, "ENTER 'y' THEN 1 FOR PRIVATE", UINT32, UINT32MAX);
                if (appreq.psid == 1)
                    appreq.psid = 13;
            }
            break;

        case 's':
            if (wsmp_psid == 1) {
                set_args(&wsmtxreq.psid,
                         "WSMP ACM", UINT32,
                         UINT32MAX);
                if (wsmtxreq.psid == 1) {
                    wsmtxreq.psid = 19;
                }
                break;
            }
            if (wsmp_psid == 1) {
//				set_args(&wsmtxreq.psid, "WSMP ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 19;
                break;
            }
            if (wbss_psid == 1) {
                set_args(&awrq.psid, "WBSS ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 19;
                break;
            }
            if (psid_user) {
                set_args(&userreq.psid, "ENTER 'y' THEN 1 FOR PUBLIC SAFETY", UINT32, UINT32MAX);
                if (userreq.psid == 1)
                    userreq.psid = 19;
            }
            else {
                set_args(&appreq.psid, "ENTER 'y' THEN 1 FOR PUBLIC SAFETY", UINT32, UINT32MAX);
                if (appreq.psid == 1)
                    appreq.psid = 19;
            }
            break;

        case 'v':
            if (wsmp_psid == 1) {
                set_args(&wsmtxreq.psid,
                         "WSMP ACM", UINT32,
                         UINT32MAX);
                if (wsmtxreq.psid == 1) {
                    wsmtxreq.psid = 20;
                }
                break;
            }
            if (wsmp_psid == 1) {
//				set_args(&wsmtxreq.psid, "WSMP ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 20;
                break;
            }
            if (wbss_psid == 1) {
                set_args(&awrq.psid, "WBSS ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 20;
                break;
            }
            if (psid_user) {
                set_args(&userreq.psid, "ENTER 'y' THEN 1 FOR VEHICLE SAFETY", UINT32, UINT32MAX);
                if (userreq.psid == 1)
                    userreq.psid = 20;
            }
            else {
                set_args(&appreq.psid, "ENTER 'y' THEN 1 FOR VEHICLE SAFETY", UINT32, UINT32MAX);
                if (appreq.psid == 1)
                    appreq.psid = 20;
            }
            break;

        case 'i':
            if (wsmp_psid == 1) {
                set_args(&wsmtxreq.psid,
                         "WSMP ACM", UINT32,
                         UINT32MAX);
                if (wsmtxreq.psid == 1) {
                    wsmtxreq.psid = 21;
                }
                break;
            }
            if (wsmp_psid == 1) {
//				set_args(&wsmtxreq.psid, "WSMP ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 21;
                break;
            }
            if (wbss_psid == 1) {
                set_args(&awrq.psid, "WBSS ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 21;
                break;
            }
            if (psid_user) {
                set_args(&userreq.psid, "ENTER 'y' THEN 1 FOR INTERNET ACCESS", UINT32, UINT32MAX);
                if (userreq.psid == 1)
                    userreq.psid = 21;
            }
            else {
                set_args(&appreq.psid, "ENTER 'y' THEN 1 FOR INTERNET ACCESS", UINT32, UINT32MAX);
                if (appreq.psid == 1)
                    appreq.psid = 21;
            }
            break;

        case 'm':
            if (wsmp_psid == 1) {
                set_args(&wsmtxreq.psid,
                         "WSMP ACM", UINT32,
                         UINT32MAX);
                if (wsmtxreq.psid == 1) {
                    wsmtxreq.psid = 23;
                }
                break;
            }
            if (wsmp_psid == 1) {
//				set_args(&wsmtxreq.psid, "WSMP ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 23;
                break;
            }
            if (wbss_psid == 1) {
                set_args(&awrq.psid, "WBSS ACM", UINT32, UINT32MAX);
                if (awrq.psid == 1)
                    awrq.psid = 23;
                break;
            }
            if (psid_user) {
                set_args(&userreq.psid, "ENTER 'y' THEN 1 FOR SECURITY", UINT32, UINT32MAX);
                if (userreq.psid == 1)
                    userreq.psid = 23;
            }
            else {
                set_args(&appreq.psid, "ENTER 'y' THEN 1 FOR SECURITY", UINT32, UINT32MAX);
                if (appreq.psid == 1)
                    appreq.psid = 23;
            }
            break;

        case ESC:
            if (wsmp_psid == 1) {
                dispmenu = WSMP;
                break;
            }
            if (wbss_psid == 1) {
                dispmenu = WBSS;
                wbss_psid = 0;
                break;
            }
            if (psid_user)
                dispmenu = USER;
            else
                dispmenu = PROVIDER;
            break;

        default:
            change = 0;

    }
    sprintf(status_msg, "TSF Timer: Result=%d", appreq.psid);
    clr_status_msg();
    if (psid_user)
        sprintf(status_msg, "psid = %u", userreq.psid);
    else
        sprintf(status_msg, "psid = %u", appreq.psid);
    return change;
}

int handler_provider(char choice) {
    int change = 1;

    switch (choice) {


        case 'r':
            app_registration(WME_ADD_PROVIDER);
            break;

        case 'u':
            app_registration(WME_DEL_PROVIDER);
            break;

        case 'y':
            psid_user = 0;
            dispmenu = PSID;
            break;

        case 'f':
            set_args(&appreq.acf, "PST ACF", STRING, UINT8MAX);
            break;

        case 'p':
            set_args(&appreq.priority, "PST Priority", UINT8, 63);
            break;

        case 'c':
            set_args(&appreq.channel, "PST Channel", UINT8, UINT8MAX);
            break;

        case 'i':
            set_args(&appreq.ipv6addr, "PST Service IP", ADDR_IPV6, 0);
            break;

        case 's':
            set_args(&appreq.serviceport, "PST Service Port", UINT16, UINT16MAX);
            break;

        case 'd':
            //set_args(&pst.addressing, "PST DevAddr", UINT8, UINT8MAX);
            break;

        case 'h':
            set_args(&appreq.macaddr, "PST PeerMACAddr", ADDR_MAC, 12);
            break;

        case ESC:
            dispmenu = APPREG;
            break;

        default:
            change = 0;

    }

    return change;
}

int handler_user(char choice) {
    int change = 1;
    switch (choice) {

        case 'r':
            app_registration(WME_ADD_USER);
            break;

        case 'u':
            app_registration(WME_DEL_USER);
            break;

        case 'y':
            psid_user = 1;
            dispmenu = PSID;
            break;

        case 'a':
            userreq.userreqtype = USER_REQ_SCH_ACCESS_AUTO_UNCONDITIONAL;
            set_args(&userreq.channel, "Channel", UINT8, UINT8MAX);
            set_args(&userreq.schextaccess, "0:Alternative,1:Continues", UINT16, UINT16MAX);
            usrReqFlag = 1;
            break;

        case 'c':
            //set_args(&ust.confirm, "UST ConfirmBeforeJoin", BOOL, 1);
            //if (ust.confirm) {
            //set_args(&desire2join, "Joining Desiration", BOOL, 1);
            //}
            break;

        case 'h':
            //set_args(&ust.match_any, "UST MatchAnyACM", BOOL, 1);
            break;

        case 'i':
            set_args(&userreq.ipv6addr, "UST Service IP", ADDR_IPV6, 0);
            break;

        case 's':
            set_args(&userreq.serviceport, "UST Service Port", UINT16, UINT16MAX);
            break;

        case ESC:
            dispmenu = APPREG;
            break;

        default:
            change = 0;

    }

    return change;
}


int handler_wbss(char choice) {
    int change = 1;
    switch (choice) {

        case 's':
            app_request(APP_ACTIVE);
            break;

        case 'e':
            app_request(APP_INACTIVE);
            break;

        case 'u':
            app_request(APP_UNAVAILABLE);
            break;

        case 'a':
            wbss_psid = 1;
            dispmenu = PSID;
            break;

        case 'f':
            set_args(&awrq.acf, "WBSS ACF", STRING, UINT8MAX);
            break;

        case 'h':
            set_args(&awrq.macaddr, "WBSS PeerMAC Addr", ADDR_MAC, 12);
            break;

        case 'r':
            set_args(&awrq.repeats, "WBSS Repeats", UINT8, 7);
            break;

        case 'p':
            set_args(&awrq.persistence, "WBSS Persistence", UINT8, 1);
            break;

        case 'c':
            set_args(&awrq.channel, "WBSS Channel", UINT8, UINT8MAX);
            break;

        case ESC:
            dispmenu = MAIN;
            break;

        default:
            change = 0;

    }

    return change;
}

int handler_wsmp(char choice) {
    int change = 1;

    switch (choice) {

        case 'x':
            tx_wsmpkt();
            break;

        case 'e':
            set_args(&txrepeat, "TxRepeat", UINT16, UINT16MAX);
            break;

        case 'd':
            set_args(&txdelay, "Tx Delay(micro secs)", UINT32, UINT32MAX);
            break;

        case 'v':
            set_args(&wsmtxreq.version, "WSM Version", UINT8, UINT8MAX);
            break;

        case 's':
            set_args(&wsmtxreq.security, "WSM Security", UINT8, UINT8MAX);
            break;

        case 'c':
            set_args(&wsmtxreq.chaninfo.channel, "WSM Channel", UINT8, UINT8MAX);
            break;

        case 'r':
            set_args(&wsmtxreq.chaninfo.rate, "WSM Rate", RATESET, UINT8MAX);
            break;

        case 'p':
            set_args(&wsmtxreq.chaninfo.txpower, "WSM TxPower", UINT8, 64);
            break;

        case 't':
            set_args(&wsmtxreq.txpriority, "WSM TxPrority", UINT8, 7);
            break;

        case 'a':
            wsmp_psid = 1;
            dispmenu = PSID;
            break;

        case 'w':
            set_args(wsmtxreq.data.contents, "WSM Data", STRINGLONG, HALFK);
            wsmtxreq.data.length = strlen(wsmtxreq.data.contents);
            break;

        case 'h':
            set_args(&wsmtxreq.macaddr, "WSM PeerMACAddr", ADDR_MAC, 12);
            break;

        case 'g':
            build_gps_wsmpacket(0, &wsmtxreq, &gpsdata, TX_GPS);
            break;

        case ESC:
            dispmenu = MAIN;
            break;

        default:
            change = 0;

    }

    return change;
}

int handler_wrss(char choice) {
    int change = 1;

    switch (choice) {

        case 'g':
            wrss_request();
            change = 0;
            break;

        case 'h':
            set_args(&wrssrq.macaddr, "WRSS Peer MAC Address", ADDR_MAC, 12);
            break;

        case 'c':
            set_args(&wrssrq.wrssreq_elem.request.channel, "WRSS Channel", UINT8, UINT8MAX);
            break;

        case 'd':
            set_args(&wrssrq.wrssreq_elem.request.duration, "WRSS Measurment Duration", UINT16, UINT16MAX);
            break;

        case ESC:
            dispmenu = MAIN;
            break;

        default:
            change = 0;
    }

    return change;
}


int handler_log(char choice) {
    int change = 1;
    char dummy[15];

    switch (choice) {

        case 'l':
            set_args(&logenabled, "Enable WSMP packet Log", BOOL, 1);
            if (logenabled) {
                clr_status_msg();
                set_logging_mode(0);
                set_logging_format(logformat);
                set_logfile(logfile);
                open_log(0);
                strncpy(dummy, get_logfile(), 14);

                if (strlen(get_logfile()) > 14)
                    dummy[14] = '\0';
                else
                    dummy[strlen(get_logfile())] = '\0';

                sprintf(status_msg, "Logging to %s, Enabled", dummy);
                print_board();
            } else {
                if (open_log(0) >= 0) close_log(0); // if file is opened for logging
                clr_status_msg();
                sprintf(status_msg, "Logging Disabled");
                print_board();
            }
            break;

        case 't':
            set_args(&logformat, "Log Type(0->Default, 1->XML, 2->CSV)?", UINT8, 2);
            set_logging_format(logformat);
            break;

        case 'f':
            set_args(logfile, "LOG File Name", STRINGLONG, 255);
            break;
/*
	case 'c':
		set_args(&capture, "Capture Forwarded Packets?", BOOL, 1);
		if(capture) {
			start_capture();
		} else {
			stop_capture();
		}
	break;

	case 'i':
		set_args(&listenlogip.sin6_addr, "IP for Capture", ADDR_IPV4, 0);
		set_logging_addr(listenlogip, listenlogport);
	break;

	case 'o':
		set_args(&listenlogport, "PORT for Capture", UINT16, UINT16MAX);
		set_logging_addr(listenlogip, listenlogport);
	break;
*/
        case ESC:
            dispmenu = MAIN;
            break;

        default:
            change = 0;
    }

    return change;
}


//*********************Display Routines*****************************************
void print_board() {
    int i = 0;
    if (dofwd) return;
    fill_board();
    //int numbytes;
    printf("\033[2J\n");
    for (i = 0; i < DISPLINES; i++)
        printf("        %s\n", board[i]);

}


void fill_board() {
    int i = 0, j = 0, msglen = 0;
    char msg[50];
    char str[INET6_ADDRSTRLEN];

    for (i = 0; i < DISPLINES; i++)
        for (j = 0; j < DISPCHARS; j++)
            board[i][j] = ' ';

    for (j = 0; j < DISPCHARS; j++) {
        board[0][j] = '*';
        board[2][j] = '*';
        board[DISPLINES - 3][j] = '*';
        board[DISPLINES - 2][j] = ' ';
        board[DISPLINES - 1][j] = '*';
    }

    for (i = 0; i < DISPLINES - 1; i++) {
        board[i][0] = '*';
        board[i][DISPCHARS - 1] = '*';
        board[i][25] = (notifrcvd && 0) ? '+' : '*';
        board[i][DISPCHARS] = '\0';
    }

    notifrcvd = 0;

    board[DISPLINES - 2][25] = ' ';

    sprintf(msg, "ARADA System's WAVE Demo Application v3.23");
    msglen = strlen(msg);
    strncpy(board[1] + 4, msg, msglen);


    fill_rxmenu();

    sprintf(msg, "%s Quit", (overIP == 0) ? "[Q]" : "[Ctrl-C]");
    msglen = strlen(msg);
    strncpy(board[DISPLINES - 8] + 3, msg, msglen);

    sprintf(msg, "%s", status_msg);
    msglen = strlen(msg);
    strncpy(board[DISPLINES - 2] + (DISPCHARS - strlen(status_msg)) / 2, msg, msglen);

    sprintf(msg, "************************");
    msglen = strlen(msg);
    strncpy(board[20] + 1, msg, msglen);

    if (overIP == 0) {
        sprintf(msg, "<WSMP Statistics>");
        msglen = strlen(msg);
        strncpy(board[21] + 16, msg, msglen);
    } else if (overIP == 1) {
        sprintf(msg, "<GPS-UDP Statistics>");
        msglen = strlen(msg);
        strncpy(board[21] + 15, msg, msglen);
    } else {
        sprintf(msg, "<GPS-IP Statistics>");
        msglen = strlen(msg);
        strncpy(board[21] + 16, msg, msglen);
    }
    if (capture) {
        sprintf(msg, "<GPS-CAPTURE Statistics>");
        msglen = strlen(msg);
        strncpy(board[21] + 16, msg, msglen);
    }
    if (overIP == 0) {
        sprintf(msg, "Transmitted: %u", numtx);
        msglen = strlen(msg);
        strncpy(board[22] + 3, msg, msglen);

        sprintf(msg, "Bytes: %u", sizetx);
        msglen = strlen(msg);
        strncpy(board[23] + 3, msg, msglen);
    } else {
        if (!dofwd) {
            if (!capture) {
                sprintf(msg, "Use xmitgpswave to");
                msglen = strlen(msg);
                strncpy(board[22] + 2, msg, msglen);
                sprintf(msg, "transmit GPS over %s", (overIP == 1) ? "UDP" : "IP");
                msglen = strlen(msg);
                strncpy(board[23] + 2, msg, msglen);
            } else {
                sprintf(msg, "Capturing packets on");
                msglen = strlen(msg);
                strncpy(board[22] + 2, msg, msglen);
                sprintf(msg, "%s:%u", inet_ntop(AF_INET6, &listenlogip.sin6_addr, str, sizeof(str)), listenlogport);
                msglen = strlen(msg);
                strncpy(board[23] + 2, msg, msglen);
            }
        } else {
            sprintf(msg, "Forwarding packets to");
            msglen = strlen(msg);
            strncpy(board[22] + 2, msg, msglen);
            if (ipvfour == 1)
                sprintf(msg, "%s:%u", inet_ntop(AF_INET, &their_addr_fwd4.sin_addr, str, sizeof(str)),
                        ntohs(their_addr_fwd4.sin_port));
            else if (ipvfour == 0)
                sprintf(msg, "%s:%u", inet_ntop(AF_INET6, &their_addr_fwd6.sin6_addr, str, sizeof(str)),
                        ntohs(their_addr_fwd6.sin6_port));
            msglen = strlen(msg);
            strncpy(board[23] + 2, msg, msglen);
        }
    }

    switch (dispmenu) {
        case MAIN:
            fill_mainmenu();
            break;

        case APPREG:
            fill_appregmenu();
            break;

        case WBSS:
            fill_wbssmenu();
            break;

        case WSMP:
            fill_wsmpmenu();
            break;

        case WRSS:
            fill_wrssmenu();
            break;

        case GET:
            fill_getmenu();
            break;

        case SET:
            fill_setmenu();
            break;

        case LOG:
            fill_logmenu();
            break;

        case PROVIDER:
            fill_providermenu();
            break;

        case USER:
            fill_usermenu();
            break;

        case PSID:
            fill_psidmenu();
            break;
    }

    for (i = 0; i < DISPLINES; i++)
        for (j = 0; j < DISPCHARS - 1; j++)
            if ((board[i][j] == '\0') || (board[i][j] == '\n')) board[i][j] = ' ';


}

void fill_rxmenu() {
    int msglen = 0, i = 0;
    char msg[50];
//	static int packetnum = 0;
    if (!gpsrcvd && (overIP == 0) && !capture && (valid_bsm == 0)) {
        sprintf(msg, "<WSM PACKET>");
        msglen = strlen(msg);
        strncpy(board[3] + 31, msg, msglen);

        sprintf(msg, "Version:%u", wsmrxind.version);
        msglen = strlen(msg);
        strncpy(board[5] + 30, msg, msglen);

        sprintf(msg, "Security:%u", wsmrxind.security);
        msglen = strlen(msg);
        strncpy(board[6] + 30, msg, msglen);

        sprintf(msg, "Channel:%u", wsmrxind.chaninfo.channel);
        msglen = strlen(msg);
        strncpy(board[7] + 30, msg, msglen);

        if (wsmrxind.chaninfo.rate > 0 && wsmrxind.chaninfo.rate <= RATESET_NUM_ELMS)
            sprintf(msg, "Rate:%3.1f", rate_set[wsmrxind.chaninfo.rate]);
        else
            sprintf(msg, "Rate:NotSet");

        msglen = strlen(msg);
        strncpy(board[8] + 30, msg, msglen);

        sprintf(msg, "Tx Power:%u", wsmrxind.chaninfo.txpower);
        msglen = strlen(msg);
        strncpy(board[9] + 30, msg, msglen);

        sprintf(msg, "PSID:%u", wsmrxind.psid);
        msglen = strlen(msg);
        strncpy(board[10] + 30, msg, msglen);

        //strncpy(board[11] + 30, msg, msglen);


        sprintf(msg, "WSM Data(Len=%3u)", wsmrxind.data.length);
        msglen = strlen(msg);
        strncpy(board[14] + 30, msg, msglen);
        for (i = 0; i < 5; i++)
            *(board[15] + 27 + i) = wsmrxind.data.contents[i];
        //strncpy(board[16] + 27, wsmrxind.data.contents + MSGWIDTH, MSGWIDTH);
        //strncpy(board[17] + 27, wsmrxind.data.contents + MSGWIDTH * 2, MSGWIDTH);
        //strncpy(board[18] + 27, wsmrxind.data.contents + MSGWIDTH * 3, MSGWIDTH);
    } else {
        if (overIP == 0) {
            sprintf(msg, "<GPS WSMP PACKET>");
        } else if (overIP == 1) {
            sprintf(msg, "<GPS UDP PACKET>");
        } else {
            sprintf(msg, "<GPS IP PACKET>");
        }
        if (caprcvd) {
            sprintf(msg, "<GPS CAPTURED PKT>");
        }
        msglen = strlen(msg);
        strncpy(board[3] + 29, msg, msglen);

        if (!capture && (overIP == 0) && !valid_bsm) {
            sprintf(msg, "Ver:%3u   Sec:%2u", wsmrxind.version, wsmrxind.security);
            msglen = strlen(msg);
            strncpy(board[5] + 27, msg, msglen);

            sprintf(msg, "Chan:%3u TxPwr:%2u", wsmrxind.chaninfo.channel, wsmrxind.chaninfo.txpower);
            msglen = strlen(msg);
            strncpy(board[6] + 27, msg, msglen);
            if (wsmrxind.chaninfo.rate > 0 && wsmrxind.chaninfo.rate <= RATESET_NUM_ELMS)
                sprintf(msg, "Rate:%3.1f", rate_set[wsmrxind.chaninfo.rate]);
            else
                sprintf(msg, "Rate:NotSet");

            msglen = strlen(msg);
            strncpy(board[7] + 27, msg, msglen);
            sprintf(msg, "PSID:%u RSSI:%2u", wsmrxind.psid, wsmrxind.rssi);
            msglen = strlen(msg);
            strncpy(board[8] + 27, msg, msglen);

        }

        if (overIP == 0 && (valid_bsm == 0)) {
            //	sprintf(msg,"Pkt#:%3lu   RSSI:%2u", (BIGENDIAN)? swap32(addwsmp.packetnum):addwsmp.packetnum, addwsmp.rssi);
            sprintf(msg, "Pkt#:%llu ", numrx);
            msglen = strlen(msg);
            strncpy(board[4] + 27, msg, msglen);
        } else {
            if (valid_bsm == 0) {
                sprintf(msg, "Packet#:%3lu", (BIGENDIAN) ? swap32(addwsmp.packetnum) : addwsmp.packetnum);
                msglen = strlen(msg);
                strncpy(board[4] + 27, msg, msglen);
                sprintf(msg, "RSSI:%3u", addwsmp.rssi);
                msglen = strlen(msg);
                strncpy(board[5] + 27, msg, msglen);
            }
        }
        if (gpsrcvd) {
            sprintf(msg, "Time:%10.0lf s", (double) rxgpsdata.time);
            msglen = strlen(msg);
            strncpy(board[10] + 27, msg, msglen);
            sprintf(msg, "Lat :%3.8lf %c", (double) rxgpsdata.latitude, (rxgpsdata.latitude > 0) ? 'N' : 'S');
            msglen = strlen(msg);
            strncpy(board[11] + 27, msg, msglen);
            sprintf(msg, "Long:%3.8lf %c", (double) rxgpsdata.longitude, (rxgpsdata.longitude > 0) ? 'E' : 'W');
            msglen = strlen(msg);
            strncpy(board[12] + 27, msg, msglen);
            sprintf(msg, "Alt :%4.3lf mtrs", (double) rxgpsdata.altitude);
            msglen = strlen(msg);
            strncpy(board[13] + 27, msg, msglen);
            sprintf(msg, "Speed:%4.2lf m/s", (double) rxgpsdata.speed);
            msglen = strlen(msg);
            strncpy(board[14] + 27, msg, msglen);
            sprintf(msg, "Direction:%3.2lf deg", (double) rxgpsdata.course);
            msglen = strlen(msg);
            strncpy(board[15] + 27, msg, msglen);

            sprintf(msg, "VDOP:%3.2lf", (double) rxgpsdata.vdop);
            msglen = strlen(msg);
            strncpy(board[17] + 27, msg, msglen);
            sprintf(msg, "HDOP:%3.2lf TOW:%3.1lf", (double) rxgpsdata.hdop, rxgpsdata.tow);
            msglen = strlen(msg);
            strncpy(board[16] + 27, msg, msglen);
            sprintf(msg, "NSV:%2u FIX:%1u", rxgpsdata.numsats, rxgpsdata.fix);
            msglen = strlen(msg);
            strncpy(board[18] + 27, msg, msglen);
        } else if (valid_bsm) {
            sprintf(msg, "Pkt#:%llu", numrx);
            msglen = strlen(msg);
            strncpy(board[4] + 27, msg, msglen);
            sprintf(msg, "Ver:%3u   Sec:%2u", wsmrxind.version, wsmrxind.security);
            msglen = strlen(msg);
            strncpy(board[5] + 27, msg, msglen);

            sprintf(msg, "Chan:%3u TxPwr:%2u", wsmrxind.chaninfo.channel, wsmrxind.chaninfo.txpower);
            msglen = strlen(msg);
            strncpy(board[6] + 27, msg, msglen);
            if (wsmrxind.chaninfo.rate > 0 && wsmrxind.chaninfo.rate <= RATESET_NUM_ELMS)
                sprintf(msg, "Rate:%3.1f", rate_set[wsmrxind.chaninfo.rate]);
            else
                sprintf(msg, "Rate:NotSet");

            msglen = strlen(msg);
            strncpy(board[7] + 27, msg, msglen);
            sprintf(msg, "PSID:%u RSSI:%u", wsmrxind.psid, wsmrxind.rssi);
            msglen = strlen(msg);
            strncpy(board[8] + 27, msg, msglen);

            sprintf(msg, "Year:%uMon:%udate:%u ", year_val, month_val, day_val);
            msglen = strlen(msg);
            strncpy(board[10] + 27, msg, msglen);

            sprintf(msg, "Lat :%d %c", latitude_val, (latitude_val > 0) ? 'N' : 'S');
            msglen = strlen(msg);
            strncpy(board[11] + 27, msg, msglen);

            sprintf(msg, "Long :%d %c", longitude_val, (longitude_val > 0) ? 'E' : 'W');
            msglen = strlen(msg);
            strncpy(board[12] + 27, msg, msglen);

            sprintf(msg, "Alt :%hu mtrs", (BIGENDIAN) ? altitude_val : swap16(altitude_val));
            msglen = strlen(msg);
            strncpy(board[13] + 27, msg, msglen);

            sprintf(msg, "Speed:%hu m/s", (BIGENDIAN) ? speed_val : swap16(speed_val));
            msglen = strlen(msg);
            strncpy(board[14] + 27, msg, msglen);

            sprintf(msg, "Direction:%ld deg", heading_val);
            msglen = strlen(msg);
            strncpy(board[15] + 27, msg, msglen);


        } else {
            sprintf(msg, "[GPS Data]");
            msglen = strlen(msg);
            strncpy(board[8] + 30, msg, msglen);
            for (i = 0; i < MSGWIDTH; i++)
                *(board[9] + 27 + i) = wsmrxind.data.contents[i];
            strncpy(board[10] + 27, wsmrxind.data.contents + MSGWIDTH, MSGWIDTH);
            strncpy(board[11] + 27, wsmrxind.data.contents + MSGWIDTH * 2, MSGWIDTH);
            strncpy(board[12] + 27, wsmrxind.data.contents + MSGWIDTH * 3, MSGWIDTH);
            strncpy(board[13] + 27, wsmrxind.data.contents + MSGWIDTH * 4, MSGWIDTH);
            strncpy(board[14] + 27, wsmrxind.data.contents + MSGWIDTH * 5, MSGWIDTH);
            strncpy(board[15] + 27, wsmrxind.data.contents + MSGWIDTH * 6, MSGWIDTH);
            strncpy(board[16] + 27, wsmrxind.data.contents + MSGWIDTH * 7, MSGWIDTH);
            strncpy(board[17] + 27, wsmrxind.data.contents + MSGWIDTH * 8, MSGWIDTH);
            strncpy(board[18] + 27, wsmrxind.data.contents + MSGWIDTH * 9, MSGWIDTH);
        }

    }

    if (overIP > 0) {
        sprintf(msg, "SRC=%02X:%02X:%02X:%02X:%02X:%02X",
                addwsmp.macaddr[0], addwsmp.macaddr[1], addwsmp.macaddr[2], addwsmp.macaddr[3], addwsmp.macaddr[4],
                addwsmp.macaddr[5]);
    } else {
        sprintf(msg, "SRC=%s", mac_sprintf(wsmrxind.macaddr));
    }
    msglen = strlen(msg);
    strncpy(board[19] + 27, msg, msglen);

    sprintf(msg, "************************");
    msglen = strlen(msg);
    strncpy(board[20] + 25, msg, msglen);

    sprintf(msg, "Received: %llu", numrx);
    msglen = strlen(msg);
    strncpy(board[22] + 29, msg, msglen);

    sprintf(msg, "Bytes: %llu", (u_int64_t) sizerx);
    msglen = strlen(msg);
    strncpy(board[23] + 29, msg, msglen);


}


void fill_mainmenu() {
    int msglen = 0, srow = 5, col = 3, items = 12;
    int i = 0;
    char msg[50];
    char title[] = "MAIN MENU";
    char key[] = {'a', 'b', 'w', 'r', 't', 'i', 'c', 'e', 'g', 's', 'l', '/'};
    char *item[] = {"APPLICATION ",
                    "WBSS",
                    "WSMP",
                    "WRSS",
                    "Get TSF Timer",
                    "CancelTX:ACI",
                    "CancelTX:Channel",
                    "CANCEL TX",
                    "Get Param",
                    "Set Param",
                    "Log Messages",
                    "Refresh Board"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}


void fill_appregmenu() {
    int msglen = 0, srow = 5, col = 3, items = 5;
    int i = 0;
    char msg[50];
    char title[] = "APP REG.MENU";
    char key[] = {'p', 'u', 'i', 'o', 'z'};
    char *item[] = {"Reg/UnReg Provider",
                    "Reg/UnReg User",
                    "Notification IP",
                    "Notification Port",
                    "Previous Menu  "
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        msglen = strlen(msg);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        strncpy(board[srow + i] + col, msg, msglen);
    }

}

void fill_providermenu() {
    int msglen = 0, srow = 5, col = 3, items = 11;
    int i = 0;
    char msg[50];
    char title[] = "APP-PROVIDER MENU";
    char key[] = {'r', 'u', 'y', 'f', 'p', 'c', 'i', 's', 'd', 'h', 'z'};
    char *item[] = {"Reg. Provider",
                    "UnReg. Provider",
                    "PSID",
                    "ACF",
                    "App. Priority",
                    "ChannelSelection",
                    "Service IP",
                    "Service Port",
                    "Device Addressing",
                    "Peer MAC Address",
                    "Previous Menu"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}

void fill_psidmenu() {
    int msglen = 0, srow = 5, col = 3, items = 6;
    int i = 0;
    char msg[50];
    char title[] = "APP-PSID MENU";
    char key[] = {'t', 'p', 's', 'v', 'i', 'm'};
    char *item[] = {"Traffic Control",
                    "Private",
                    "Public Safety",
                    "Vehicle Safety",
                    "Internet access",
                    "Security manager"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}


void fill_usermenu() {
    int msglen = 0, srow = 5, col = 3, items = 8;
    int i = 0;
    char msg[50];
    char title[] = "APP-USER MENU";
    char key[] = {'r', 'u', 'y', 'a', 'c', 'h', 'i', 's', 'z'};
    char *item[] = {"Reg. User",
                    "UnReg. User",
                    "PSID",
                    "UsrReqType",
                    "ConfirmBeforeJoin",
                    "MatchAnyACM",
                    "Service IP",
                    "Service Port",
                    "Previous Menu"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}

void fill_wbssmenu() {
    int msglen = 0, srow = 5, col = 3, items = 10;
    int i = 0;
    char msg[50];
    char title[] = "WBSS MENU";
    char key[] = {'s', 'e', 'u', 'a', 'f', 'h', 'r', 'p', 'c', 'z'};
    char *item[] = {"Start WBSS ",
                    "End WBSS",
                    "Make Unavailable",
                    "PSID",
                    "ACF",
                    "Peer MAC Address",
                    "Repeats",
                    "Persistence",
                    "ChannelSelection",
                    "Previous Menu"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}


void fill_wsmpmenu() {
    int msglen = 0, srow = 5, col = 3, items = 14;
    int i = 0;
    char msg[50];
    char title[] = "WSMP MENU";
    char key[] = {'x', 'e', 'd', 'v', 's', 'c', 'r', 'p', 't', 'a', 'w', 'h', 'g', 'z'};
    char *item[] = {"TX WSMP Packet",
                    "Tx Repeat",
                    "Tx Delay",
                    "Version",
                    "Security",
                    "Channel",
                    "Rate",
                    "Tx Power",
                    "Tx Priority",
                    "PSID",
                    "WSM",
                    "Peer MAC Address",
                    "GPS=>WSM",
                    "Previous Menu"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }

}


void fill_wrssmenu() {
    int msglen = 0, srow = 5, col = 3, items = 5;
    int i = 0;
    char msg[50];
    char title[] = "WRSS MENU";
    char key[] = {'g', 'h', 'c', 'd', 'z'};
    char *item[] = {"Get WRSS Report ",
                    "Peer MAC Addr",
                    "Channel",
                    "Duration",
                    "Previous Menu"
    };

    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}

void fill_logmenu() {
    int msglen = 0, srow = 5, col = 3, items = 4;
    int i = 0;
    char msg[50];
    char title[] = "LOG MENU";
    char key[] = {'f', 't', 'l', 'z'};
    char *item[] = {"Log FILE",
                    "Log Type",
                    "Start/Stop WSMPLOG",
                    "Previous Menu"
    };

/*	char key[] = {'f', 't', 'l', 'c', 'i', 'o', 'z'};
	char *item[] = {	"Log FILE",
				"Log Type",
				"Enable WSMP Logging",
				"Capture Fwd Pkts?",
				"IP for Capturing",
				"PORT for Capturing",
				"Previous Menu"
			};
*/
    sprintf(msg, "<%s>", title);
    msglen = strlen(msg);
    strncpy(board[srow - 2] + col + 4, msg, msglen);

    for (i = 0; i < items; i++) {
        sprintf(msg, "[%c] %s", toupper(key[i]), item[i]);
        if (key[i] == 'z')
            sprintf(msg, "[ESC] %s", item[i]);
        msglen = strlen(msg);
        strncpy(board[srow + i] + col, msg, msglen);
    }
}


void fill_getmenu() {
//	int msglen = 0;
//	char msg[50];



}

void fill_setmenu() {
//	int msglen = 0;
//	char msg[50];


}

//********Helpers*********************************

int extract_bool(char *str) {
    int len = strlen(str);
//	int i = 0;

    if (len != 1)
        return -1;

    return ((str[0] != '0') && (str[0] != '1')) ? -1 : str[0] - '0';
}


u_int32_t extract_uint(char *str) {
    int len = strlen(str);
    int i = 0;
    u_int32_t value;
    for (i = 0; i < len; i++) {
        if (!isdigit(str[i]))
            return -1;
    }

    sscanf(str, "%u", &value);
    return value;
}


int extract_macaddr(u_int8_t *mac, char *str) {
    int maclen = IEEE80211_ADDR_LEN;
    int len = strlen(str);
    int i = 0, j = 0, octet = 0, digits = 0, ld = 0, rd = 0;
    char num[2];
    u_int8_t tempmac[maclen];
    memset(tempmac, 0, maclen);

    if ((len < (2 * maclen - 1)) || (len > (3 * maclen - 1)))
        return -1;

    while (i < len) {
        j = i;

        while (str[i] != ':' && (i < len)) i++;

        if (i > len) exit(0);
        digits = i - j;

        if ((digits > 2) || (digits < 1) || (octet >= maclen))
            return -1;

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

int extract_rate(char *str) {
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


float index_to_rate(u_int8_t rix) {
    return ((rix < 1) || (rix >= RATESET_NUM_ELMS)) ? -1 : rate_set[rix];
}


//***************************UTILITY**********************************************
const char *
mac_sprintf(const u_int8_t *mac) {
    static char etherbuf[18];
    snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return etherbuf;
}


//***************************Key Handlers**************************************
int kbhit() {
    char ch;
    int nread;

    if (dofwd) return 0;
    if (peek != -1)
        return 1;
    newtc.c_cc[VMIN] = 0;
    tcsetattr(0, TCSANOW, &newtc);
    nread = read(0, &ch, 1);
    tcsetattr(0, TCSANOW, &old);

    if (nread == 1) {
        peek = ch;
        return 1;
    }
    return 0;
}

int getch() {
    char ch;

    if (peek != -1) {
        ch = peek;
        peek = -1;
        return ch;
    }

    newtc.c_cc[VMIN] = 1;
    tcsetattr(0, TCSANOW, &newtc);
    read(0, &ch, 1);
    tcsetattr(0, TCSANOW, &old);

    return ch;
}


void ansi_init() {
    tcgetattr(0, &old);
    newtc = old;
    newtc.c_lflag &= ~ICANON;
    newtc.c_lflag &= ~ECHO;
    newtc.c_lflag &= ~ISIG;
    newtc.c_cc[VTIME] = 0;
    return;
}

void clr_status_msg() {
    int i = 0;
    for (i = 0; i < STMSGWIDTH - 1; i++)
        status_msg[i] = ' ';
    status_msg[STMSGWIDTH - 1] = '\0';
}


/*static uint8_t
getrssi(int s, const char* ifname)
{
	struct iw_statistics stats;
	struct iwreq wrq;

	(void) memset(&wrq, 0, sizeof(wrq));
	wrq.u.data.pointer = (caddr_t) &stats;
	wrq.u.data.flags = 1;
	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIWSTATS, &wrq) < 0)
		return 0;
	else
		return (uint8_t)stats.qual.qual;
}*/

void *disp_thread(void *data) {
    int i = 0;
    while (1) {
        sleep(1);
        if (refresh && (!doNOTrefresh)) {
            print_board();
            refresh = 0;
        }
        if (killnow) {
            if (reqpending) {
                for (i = 3; i > 0; i--) {
                    clr_status_msg();
                    sprintf(status_msg, "Exit:Connecting with WAVEDEVICE...%d", i);
                    print_board();
                }
                clr_status_msg();
                sprintf(status_msg, "Exit:Communication timed out");
                print_board();
                tcsetattr(0, TCSANOW, &old);
                exit(1);
            }
        }

    }
}

/*
void *timer(void *data)
{
	int i = 0;
	for(i = 3; i > 0 ; i--) {
		clr_status_msg();
		sprintf(status_msg, "Exit:Connecting with WAVEDEVICE...%d",i);
		print_board();
		sleep(1);
	}
	if(killnow) {
			if(reqpending) {
					clr_status_msg();
					sprintf(status_msg, "Exit:Communication timed out");
					print_board();
					tcsetattr(0,TCSANOW, &old);
					exit(1);
			}
	}
}
*/

void bye_bye(void) {
    int ret;

    if (capture)
        stop_capture();
    else
        close_log(0);

    reqpending = 1;
    killnow = 1;
    //pthread_create(&timerthread, NULL, timer, NULL);
    ret = removeAll();
    killnow = 0;
    reqpending = 0;
    clr_status_msg();
    sprintf(status_msg, "Exit");
    print_board();
    signal(SIGINT, SIG_DFL);
    tcsetattr(0, TCSANOW, &old);
    exit(0);
}

void sig_int(void) {
    bye_bye();
}

void sig_term(void) {
    bye_bye();
}

