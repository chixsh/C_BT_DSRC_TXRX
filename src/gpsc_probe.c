#include "gpsc_probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<netinet/tcp.h> //for TCP_NODELAY
#include<sys/time.h> // for gettimeofday

static struct sockaddr_in gpsc_devaddr;
static int is_gpsc_devaddr_set = 0;

static int gpscsockfd = -1;
#define DEFAULT_DEVADDR "127.0.0.1"

char *get_gpsc_devaddr() {
    if (is_gpsc_devaddr_set)
        return inet_ntoa(gpsc_devaddr.sin_addr);
    else
        return (char *) DEFAULT_DEVADDR;
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

char *get_gps_devaddr() {
    if (is_gpsc_devaddr_set)
        return inet_ntoa(gpsc_devaddr.sin_addr);
    else
        return (char *) DEFAULT_DEVADDR;
}

char *set_gps_devaddr(char *devaddr) {
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

