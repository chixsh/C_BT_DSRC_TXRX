//
// Created by trl on 2/22/16.
//

#include "GPS_Handler.h"

int gpscsockfd = -1;


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

int isBigEndian() {
    long one = 0x00000001;
    return !(*((char *) (&one)));
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
