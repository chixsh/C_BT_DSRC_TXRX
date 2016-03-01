//
// Created by trl on 2/22/16.
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
#include <netinet/tcp.h> //for TCP_NODELAY


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
static GPSData gpsdata;

static int contents = 0;
static int dump_gpsd = 0;
static float rate_set[] = {0.0f, 3.0f, 4.5f, 6.0f, 9.0f, 12.0f, 18.0f, 24.0f, 27.0f, 36.0f, 48.0f, 54.0f};
static int firstchan = 1, firstrate = 1, firstpower = 1;
static int isVAPset = 0;
static int isNotWSMP = 0;
static char data_sys[25];
#define DEFAULT_DEVADDR "127.0.0.1"

static struct sockaddr_in gpsc_devaddr;
static int is_gpsc_devaddr_set = 0;


long get_gps_txdelay();

int get_gps_txpower();

int get_gps_txchannel();

float get_gps_txrate();

char *get_gps_vap();

int gpsc_connect(char *ip);

int gpsc_close_sock();

char *set_gpsc_devaddr(char *devaddr);

void get_gps_status(GPSData *gpsdat, char *gpsadd);

float __set_vap_txrate();

int __set_vap_txpower();

int __set_vap_txchannel();

int parseTXConfigData(WSMRequest *wsmtxreq);

char *get_gpsc_devaddr();

int isBigEndian();

int __extract_rate(char *str);
