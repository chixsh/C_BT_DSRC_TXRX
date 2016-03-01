/*

* Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

* Proprietary and Confidential Material.

*

*/

#ifndef _WIN_IF_H
#define _WIN_IF_H

#include "wave.h"
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "os.h"

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
//static char data_o[1512];

typedef struct d_gps {
    uint16_t year_d;
    uint8_t month_d;
    uint8_t date_d;
    uint8_t hour_d;
    uint8_t min_d;
    float sec_d;
    double local_tod;
} gpsdata_d;

gpsdata_d local_d;
#define LEAP(yr) ((yr%4 == 0 && yr%100 != 0) || (yr%400 == 0)? 1 : 0)

//typedef  struct table {
//    int s_val;
//}month_tab;

int lookup_mnth(int mnth, int yr) {
    int mnth_tab[] = {0 /*(in leap year 6)*/, 3 /*(in leap year 2)*/, 3, 6, 1, 4, 6, 2, 5, 0, 3, 5};
    int mnth_val;
    if (LEAP(yr) && mnth < 2) {
        if ((mnth_val = mnth_tab[mnth] - 1) < 0)
            mnth_val = 7 + mnth_val;
    }
    else {
        mnth_val = mnth_tab[mnth];
    }

    return mnth_val;
}

double get_timeofweek(gpsdata_d *gpslocal_d) {
    int century, cntry;
    char cent[6];
    int year, yr_val, mnth;
    int day;
    double timeofweek_d;

    sprintf(cent, "%d", gpslocal_d->year_d);
    year = atoi(&cent[2]);
    cent[2] = '\0';
    century = atoi(cent);
    cntry = 2 * (3 - (century % 4));
    yr_val = year + year / 4;
    mnth = lookup_mnth(gpslocal_d->month_d - 1, year);

    /* TOW = day of the week *  24 hours * 60 minutes * 60 seconds + convert reported time to seconds */
    day = (cntry + yr_val + mnth + gpslocal_d->date_d) % 7;

    return ((timeofweek_d = day * 24 * 60 * 60 + gpslocal_d->local_tod));
}

int isBigEndian() {
    long one = 0x00000001;
    return !(*((char *) (&one)));
}


int reverseByteOrder(void *dest, void *src, int size) {
    int i = 0;

    if (dest == NULL || src == NULL || size < 2)
        return -1;

    for (i = 0; i < size; i++)
        *(((unsigned char *) dest) + i) = *(((unsigned char *) src) + size - 1 - i);

    return -1;

}

const char *
__mac_sprintf(const u_int8_t *mac) {
    static char etherbuf[18];
    snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return etherbuf;
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

int get_gps_contents() {
    return contents;
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

float __set_vap_txrate() {
    sprintf(data_sys, "iwconfig %s rate %fM", get_gps_vap(), get_gps_txrate());
    printf("%s\n", data_sys);
    system(data_sys);
    return gps_txrate;
}

int toggle_dump_gpsd() {
    dump_gpsd = !dump_gpsd;
    return dump_gpsd;
}

void printGPS(GPSData *gps) {
    if (gps == NULL)
        return;
    printf("\nLat[%lf] Lon[%lf] Alt[%lf] HEE[%lf] VEE[%lf]\n", gps->latitude, gps->longitude, gps->altitude, gps->hee,
           gps->vee);
    printf("Speed[%lf] Dir[%lf] Climb[%lf] CLEE[%lf]\n", gps->speed, gps->course, gps->climb, gps->clee);
    printf("HDOP[%lf] VDOP[%lf] NSOV[%u] FIX[%u] TIM[%lf] LOCAL_TOD[%lf] LOCAL_TSF[%llu]:TOW[%lf]\n", gps->hdop,
           gps->vdop, gps->numsats, gps->fix, gps->time, gps->local_tod, gps->local_tsf, gps->tow);
}


void set_gpsmode_notWSMP() {
    if (isVAPset)
        sprintf(data_sys, "iwpriv %s ipcchpermit 1", get_gps_vap());
    else
        sprintf(data_sys, "iwpriv %s ipcchpermit 1", DEFAULT_VAP);
    printf("%s\n", data_sys);
    system(data_sys);
    if (isVAPset)
        sprintf(data_sys, "iwconfig %s txpower on", get_gps_vap());
    else
        sprintf(data_sys, "iwconfig %s txpower on", DEFAULT_VAP);
    //printf("%s\n",data_sys);
    //system(data_sys);
    isNotWSMP = 1;
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

int build_gps_wsmpacket(int sockfd, WSMRequest *wsmtxreq, GPSData *gpsdata, GPS_PACKET gpspkt) {
    additionalWSMP nodeinfo;
    char configstr[250], buf[20], *token;
    FILE *file;
    fd_set fds;
    //int ret;//, maxtokens = 25, numtokens = 0,
    int pos = 11, i = 0;
    int binaryvals = 0, prefix = 0;//, iMode;
    int big = isBigEndian();
    u_int64_t templl = 0;
    double tempd = 0.0, tempd2 = 0.0;
    static uint32_t count = 0;
    static uint32_t localpkt = 0;
    unsigned char *hwa = NULL;
    struct ifreq ifr;
    int sfd = 0;//data
    char ch = '1';
    // struct timeval tv;
    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;


    if ((wsmtxreq == NULL) || (gpsdata == NULL))
        return -1;

#ifdef    WIN32
    memset (&ifr, 0, sizeof( struct ifreq ));
    write(sockfd,&ch,1);
            read(sockfd,gpsdata,sizeof(GPSData));
    gpsdata->local_tsf = (uint64_t)generatetsfRequest();
    strcpy(ifr.ifr_name, "ath0");
    if (ioctlsocket(sfd, SIOCGIFHWADDR, &iMode)!=0)

    hwa = ifr.ifr_hwaddr.sa_data;

#else

    write(sockfd, &ch, 1);
    read(sockfd, gpsdata, sizeof(GPSData));
    gpsdata->local_tsf = (uint64_t) generatetsfRequest();
    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, "ath0");
    ioctl(sfd, SIOCGIFHWADDR, &ifr);
    hwa = (unsigned char *) ifr.ifr_ifru.ifru_hwaddr.sa_data;
    //hwa = (unsigned char*)ifr.ifr_hwaddr.sa_data;

#endif

    memset(wsmtxreq->data.contents, 0, sizeof(wsmtxreq->data.contents));
    wsmtxreq->data.length = 0;

    if (gpspkt == LOCAL_GPS) {
        localpkt++;
        nodeinfo.packetnum = localpkt;
        if (isBigEndian())
            nodeinfo.packetnum = swap32_(localpkt);
        nodeinfo.rssi = 0;
        memset(nodeinfo.macaddr, 0, 6);
    } else {
        count++;

        nodeinfo.packetnum = count;
        if (isBigEndian())
            nodeinfo.packetnum = swap32_(count);

        nodeinfo.rssi = 188;
        if (hwa) {
            for (i = 0; i < IEEE80211_ADDR_LEN; i++)
                nodeinfo.macaddr[i] = (uint8_t) hwa[i]; /*Build 1460: The cast was int*/
            //printf("#%s\n", __mac_sprintf(nodeinfo.macaddr));
        }
    }

    /*First 11 bytes are nodeinfo for GPS packets only*/
    memcpy(wsmtxreq->data.contents, &nodeinfo.packetnum, 4);
    memcpy(wsmtxreq->data.contents + 4, &nodeinfo.rssi, 1);
    memcpy(wsmtxreq->data.contents + 5, nodeinfo.macaddr, 6);
    wsmtxreq->data.length = pos;

    if (gpsdata->time > 0) {
        sprintf(wsmtxreq->data.contents + pos, "STR TIM %lf LAT %lf LON %lf ALT %lf", gpsdata->time, gpsdata->latitude,
                gpsdata->longitude, gpsdata->altitude);
        wsmtxreq->data.length = pos + strlen(wsmtxreq->data.contents);
    }


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
        return -1;
    }

    if (fgets(configstr, 200, file) < 0) {
        return -2;
    }
    fclose(file);

    configstr[strlen(configstr) - 1] = '\0';
    token = (char *) strtok(configstr, " \n");

    if (token == NULL)
        return -3;

    if (strcasecmp(token, "GPS_STR") && strcasecmp(token, "GPS_BIN")) {
        return -3;
    }

    if (!strcasecmp(token, "GPS_BIN"))
        binaryvals = 1;

    token = (char *) strtok(NULL, " \n");

    if (token == NULL) {
        return 3;

    } else if (!strcasecmp(token, "+")) {
        prefix = 1;
    }

    if (!binaryvals) {
        sprintf(buf, "STR ");
        strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
        pos += strlen(buf);

        do {
            if (token == NULL)
                return 0;

            if (!strcasecmp(token, "TIM")) {
                sprintf(buf, "%s%lf ", (prefix) ? "TIM " : " ", gpsdata->time);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            } else if (!strcasecmp(token, "TIM_TSF")) {
                /*Add TSF to the fractional part of gps time*/
                tempd2 = (int64_t)(gpsdata->local_tsf) / MILLION;
                tempd2 = tempd2 - (int) tempd2;
                tempd2 = gpsdata->time + tempd2;
                sprintf(buf, "%s%lf ", (prefix) ? "TIM_TSF " : " ", tempd2);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            } else if (!strcasecmp(token, "TOD")) {
                sprintf(buf, "%s%lf ", (prefix) ? "TOD " : " ", gpsdata->local_tod);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            } else if (!strcasecmp(token, "TSF")) {
                sprintf(buf, "%s%llu ", (prefix) ? "TSF " : " ", gpsdata->local_tsf);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            } else if (!strcasecmp(token, "LAT")) {
                sprintf(buf, "%s%lf ", (prefix) ? "LAT " : " ", gpsdata->latitude);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            } else if (!strcasecmp(token, "LON")) {
                sprintf(buf, "%s%lf ", (prefix) ? "LON " : " ", gpsdata->longitude);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "ALT")) {
                sprintf(buf, "%s%lf ", (prefix) ? "ALT " : " ", gpsdata->altitude);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "SPD")) {
                sprintf(buf, "%s%lf ", (prefix) ? "SPD " : " ", gpsdata->speed);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "DIR")) {
                sprintf(buf, "%s%lf ", (prefix) ? "DIR " : " ", gpsdata->course);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "HEE")) {
                sprintf(buf, "%s%lf ", (prefix) ? "HEE " : " ", gpsdata->hee);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "VEE")) {
                sprintf(buf, "%s%lf ", (prefix) ? "VEE " : " ", gpsdata->vee);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "HDP")) {
                sprintf(buf, "%s%lf ", (prefix) ? "HDP " : " ", gpsdata->hdop);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "VDP")) {
                sprintf(buf, "%s%lf ", (prefix) ? "VDP " : " ", gpsdata->vdop);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "NSV")) {
                sprintf(buf, "%s%u ", (prefix) ? "NSV " : " ", gpsdata->numsats);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);

            } else if (!strcasecmp(token, "FIX")) {
                sprintf(buf, "%s%u ", (prefix) ? "FIX " : " ", gpsdata->fix);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            } else if (!strcasecmp(token, "TOW")) {
                sprintf(buf, "%s%lf ", (prefix) ? "TOW " : " ", gpsdata->tow);
                printf("%s\n", buf);
                strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
                pos += strlen(buf);
            }

            token = (char *) strtok(NULL, " \n");
        } while (token != NULL);
        wsmtxreq->data.length = pos;

    } else {
        /*Fill Values in Binary*/
        sprintf(buf, "%s", (prefix) ? "BIN " : "@");
        strncpy(wsmtxreq->data.contents + pos, buf, strlen(buf));
        pos += strlen(buf);

        do {
            if (token == NULL)
                return 0;

            if (!strcasecmp(token, "TIM")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 't';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->time));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    templl = 0;
                    tempd = 0.0;
                }
                else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->time, sizeof(gpsdata->time));
                    pos += sizeof(gpsdata->time);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "TIM_TSF")) {
                /*Add TSF to the fractional part of gps time*/
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'T';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    tempd2 = (int64_t)(gpsdata->local_tsf) / MILLION;
                    tempd2 = tempd2 - (int) tempd2;
                    tempd2 = gpsdata->time + tempd2;
                    //printf("tim=%lf tsf=%llu tim_tsf=%lf\n",gpsdata->time ,gpsdata->local_tsf,  tempd2);
                    templl = swap64(*(u_int64_t * )(&tempd2));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    templl = 0;
                    tempd = 0.0;
                    tempd2 = 0.0;
                }
                else {
                    tempd2 = (int64_t)(gpsdata->local_tsf) / MILLION;
                    tempd2 = tempd2 - (int) tempd2;
                    tempd2 = gpsdata->time + tempd2;
                    //printf("tim=%lf tsf=%llu tim_tsf=%lf\n",gpsdata->time ,gpsdata->local_tsf,  tempd2);
                    memcpy(wsmtxreq->data.contents + pos, &tempd2, sizeof(tempd2));
                    pos += sizeof(tempd2);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "TOD")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'g';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->local_tod));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    templl = 0;
                    tempd = 0.0;
                }
                else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->local_tod, sizeof(gpsdata->local_tod));
                    pos += sizeof(gpsdata->local_tod);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "TSF")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'f';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->local_tsf));
                    //tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &templl, sizeof(templl));
                    pos += sizeof(templl);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    templl = 0;
                    tempd = 0.0;
                }
                else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->local_tsf, sizeof(gpsdata->local_tsf));
                    pos += sizeof(gpsdata->local_tsf);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                //printf("TX.tsf=%llu\n", gpsdata->local_tsf);
            } else if (!strcasecmp(token, "LAT")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'l';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->latitude));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->latitude, sizeof(gpsdata->latitude));
                    pos += sizeof(gpsdata->latitude);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
            } else if (!strcasecmp(token, "LON")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'n';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->longitude));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->longitude, sizeof(gpsdata->longitude));
                    pos += sizeof(gpsdata->longitude);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
            } else if (!strcasecmp(token, "ALT")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'a';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->altitude));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->altitude, sizeof(gpsdata->altitude));
                    pos += sizeof(gpsdata->altitude);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
            } else if (!strcasecmp(token, "SPD")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 's';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->speed));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->speed, sizeof(gpsdata->speed));
                    pos += sizeof(gpsdata->speed);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "DIR")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'd';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->course));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->course, sizeof(gpsdata->course));
                    pos += sizeof(gpsdata->course);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "HEE")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'h';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->hee));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->hee, sizeof(gpsdata->hee));
                    pos += sizeof(gpsdata->hee);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "VEE")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'v';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->vee));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->vee, sizeof(gpsdata->vee));
                    pos += sizeof(gpsdata->vee);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "HDP")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = '-';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->hdop));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->hdop, sizeof(gpsdata->hdop));
                    pos += sizeof(gpsdata->hdop);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "VDP")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = '|';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->vdop));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->vdop, sizeof(gpsdata->vdop));
                    pos += sizeof(gpsdata->vdop);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }

            } else if (!strcasecmp(token, "NSV")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = '#';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                memcpy(wsmtxreq->data.contents + pos, &gpsdata->numsats, sizeof(gpsdata->numsats));
                pos += sizeof(gpsdata->numsats);
                *(wsmtxreq->data.contents + pos) = ' ';
                pos++;
            } else if (!strcasecmp(token, "FIX")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'x';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                memcpy(wsmtxreq->data.contents + pos, &gpsdata->fix, sizeof(gpsdata->fix));
                pos += sizeof(gpsdata->fix);
                *(wsmtxreq->data.contents + pos) = ' ';
                pos++;
            } else if (!strcasecmp(token, "TOW")) {
                if (prefix) {
                    *(wsmtxreq->data.contents + pos) = 'w';
                    pos++;
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
                if (big) {
                    templl = swap64(*(u_int64_t * )(&gpsdata->tow));
                    tempd = *((double *) &templl);
                    memcpy(wsmtxreq->data.contents + pos, &tempd, sizeof(tempd));
                    pos += sizeof(tempd);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                    tempd = 0.0;
                    templl = 0;
                } else {
                    memcpy(wsmtxreq->data.contents + pos, &gpsdata->tow, sizeof(gpsdata->tow));
                    pos += sizeof(gpsdata->tow);
                    *(wsmtxreq->data.contents + pos) = ' ';
                    pos++;
                }
            }
            token = (char *) strtok(NULL, " \n");

        } while (token != NULL);
        *(wsmtxreq->data.contents + pos) = '\0';
        wsmtxreq->data.length = pos;
    }
    /*for(i = 0; i < 50; i++)
    printf("%d ", wsmtxreq->data.contents[i]);
    printf("\nsize=%d\n",wsmtxreq->data.length);
    */

    parseTXConfigData(wsmtxreq);
    return 0;

}

int parseGPSBinData(GPSData *gps, char *str, int len) {
    FILE *file;
    int i = 0;
    int prefixed = 0;
    char *filetok, *datatok;
    char configstr[250], data[1024];
    double tempd = 0.0;
    int big = isBigEndian();
    u_int64_t templl = 0;
    uint8_t temp;
    //int i1 = 0;

    contents = 0;
    if (gps == NULL || len == 0 || str == NULL) {
        contents |= GPS_ERR;
        return contents;
    }
    /*str should point to actual wsm data not the nodeinfo, len = length of data (without nodeinfo length)*/
    memcpy(data, str, len);
    datatok = (char *) strtok(data, " ");

    if (datatok == NULL) {
        contents |= GPS_ERR;
        return -1;
    }

    if (!strcasecmp(datatok, "STR")) {
        contents |= GPS_STG;
        return -1;
    } else if (!strcasecmp(datatok, "BIN")) {
        prefixed = 1;
        contents |= GPS_PRE;
    } else {
        contents |= GPS_BIN;
    }



    /*  Rely on the Recieved Data for Parsing */
    gps->time = NAN;
    gps->local_tod = NAN;
    gps->local_tsf = 0;
    gps->latitude = NAN;
    gps->longitude = NAN;
    gps->altitude = NAN;
    gps->speed = NAN;
    gps->course = NAN;
    gps->hee = NAN;
    gps->vee = NAN;
    gps->hdop = NAN;
    gps->vdop = NAN;
    gps->tow = NAN;

    if (prefixed) {
        memcpy(data, str, len);
        contents |= GPS_PRE;
        for (i = 0; i < len; i++) {
            switch (data[i]) {
                case 't':
                case 'T':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->time = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_TIM;
                    break;

                case 'g':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->local_tod = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_TOD;
                    break;

                case 'f':
                    memcpy(&templl, data + i + 2, sizeof(templl));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&templl));
                        //tempd = *((double *) &templl);
                    }
                    gps->local_tsf = templl;
                    //printf("rx.tsf=%llu\n", gps->local_tsf);
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_TSF;
                    break;

                case 'l':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->latitude = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_LAT;
                    break;

                case 'n':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->longitude = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_LON;
                    break;

                case 'a':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->altitude = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_ALT;
                    break;

                case 's':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->speed = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_SPD;
                    break;

                case 'd':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->course = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_DIR;
                    break;

                case 'h':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->hee = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_HEE;
                    break;

                case 'v':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->vee = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_VEE;
                    break;

                case '-':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->hdop = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_HDP;
                    break;

                case '|':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->vdop = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_VDP;
                    break;

                case '#':
                    memcpy(&temp, data + i + 2, sizeof(temp));
                    gps->numsats = temp;
                    i += 3;
                    temp = 0;
                    contents |= GPS_NSV;
                    break;

                case 'x':
                    memcpy(&temp, data + i + 2, sizeof(temp));
                    gps->fix = temp;
                    i += 3;
                    temp = 0;
                    contents |= GPS_FIX;
                    break;
                case 'w':
                    memcpy(&tempd, data + i + 2, sizeof(tempd));
                    if (big) {
                        templl = swap64(*(u_int64_t * )(&tempd));
                        tempd = *((double *) &templl);
                    }
                    gps->tow = tempd;
                    i += 10;
                    tempd = 0.0;
                    contents |= GPS_TOW;
                    break;
            }
        }

    } else {
        /* Read the Config file to Parse un-prefixed BINARY Data*/
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
            contents |= GPS_ERR;
            fclose(file);
            return -1;
        }
        if (fgets(configstr, 200, file) < 0) {
            contents |= GPS_ERR;
            fclose(file);
            return -1;
        }
        fclose(file);

        filetok = (char *) strtok(configstr, " \n");

        if (filetok == NULL) {
            contents |= GPS_ERR;
            return -1;
        }
        if (!strcasecmp(filetok, "GPS_STR")) {
            contents |= GPS_STG;
            return -1;
        }

        i = 1;

        do {
            if (filetok == NULL)
                return 0;
            if ((!strcasecmp(filetok, "TIM") || !strcasecmp(filetok, "TIM_TSF")) && i < len) {
                /*TSF can be in the fractional part of gps time, we donot set the contents with GPS_TIM_TSF however*/
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->time = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_TIM;
            } else if (!strcasecmp(filetok, "TOD") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->local_tod = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_TOD;
            } else if (!strcasecmp(filetok, "TSF") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&templl));
                    //tempd = *((double *) &templl);
                }
                gps->local_tsf = templl;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_TSF;
            } else if (!strcasecmp(filetok, "LAT") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->latitude = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_LAT;
            } else if (!strcasecmp(filetok, "LON") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->longitude = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_LON;
            } else if (!strcasecmp(filetok, "ALT") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->altitude = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_ALT;
            } else if (!strcasecmp(filetok, "SPD") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->speed = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_SPD;
            } else if (!strcasecmp(filetok, "DIR") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->course = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_DIR;
            } else if (!strcasecmp(filetok, "HEE") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->hee = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_HEE;
            } else if (!strcasecmp(filetok, "VEE") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->vee = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_VEE;
            } else if (!strcasecmp(filetok, "HDP") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->hdop = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_HDP;
            } else if (!strcasecmp(filetok, "VDP") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->vdop = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_VDP;
            } else if (!strcasecmp(filetok, "NSV") && i < len) {
                memcpy(&temp, data + i, sizeof(temp));
                gps->numsats = temp;
                i += 2;
                temp = 0;
                templl = 0;
                contents |= GPS_NSV;
            } else if (!strcasecmp(filetok, "FIX") && i < len) {
                memcpy(&temp, data + i, sizeof(temp));
                gps->fix = temp;
                i += 2;
                temp = 0;
                templl = 0;
                contents |= GPS_FIX;
            } else if (!strcasecmp(filetok, "TOW") && i < len) {
                memcpy(&tempd, data + i, sizeof(tempd));
                if (big) {
                    templl = swap64(*(u_int64_t * )(&tempd));
                    tempd = *((double *) &templl);
                }
                gps->tow = tempd;
                i += 9;
                tempd = 0.0;
                templl = 0;
                contents |= GPS_TOW;
            }
            filetok = (char *) strtok(NULL, " \n");
        } while (filetok != NULL && i < len);
    }

    return 0;
}

#endif

