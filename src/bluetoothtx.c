/*

* Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

* Proprietary and Confidential Material.

*

*/

#include <stdio.h>
#include <ctype.h>
#include <termio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>

#include "wave.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define MAX_RSP 50
//static PSTEntry entry;
static WMEApplicationRequest wreq;
static WMEApplicationRequest entry;
static WMETARequest tareq;
static WSMRequest wsmreq;
static WMECancelTxRequest cancelReq;
static int pid;

inquiry_info *info = NULL;
static int num_rsp = 0;

void receiveWME_NotifIndication(WMENotificationIndication *wmeindication);

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication);

void receiveTsfTimerIndication(TSFTimer *timer);
//int	 confirmBeforeJoin(u_int8_t acid, ACM acm);  This is for user only

int rsp_val;

#define STORAGEDIR "/var/lib/bluetooth"

int buildPSTEntry();

int buildWSMRequestPacket();

int buildWMEApplicationRequest();

int buildWMETARequest();

int txWSMPPkts(int);

void sig_int(void);

void sig_term(void);

static uint64_t packets;
static uint64_t drops = 0;
char names[10][249];
struct ta_argument {
    uint8_t channel;
    uint8_t channelinterval;
} taarg;


int dev_id = -1, dd;

static char *major_classes[] = {
        "Miscellaneous", "Computer", "Phone", "LAN Access",
        "Audio/Video", "Peripheral", "Imaging", "Uncategorized"
};

#if 0


static inline char *find_key(char *map, size_t size, const char *key, size_t len, int icase)
{
    char *ptr = map;
    size_t ptrlen = size;

    while (ptrlen > len + 1) {
        int cmp = (icase) ? strncasecmp(ptr, key, len) : strncmp(ptr, key, len);
        if (cmp == 0) {
            if (ptr == map)
                return ptr;

            if ((*(ptr - 1) == '\r' || *(ptr - 1) == '\n') &&
                            *(ptr + len) == ' ')
                return ptr;
        }

        if (icase) {
            char *p1 = memchr(ptr + 1, tolower(*key), ptrlen - 1);
            char *p2 = memchr(ptr + 1, toupper(*key), ptrlen - 1);

            if (!p1)
                ptr = p2;
            else if (!p2)
                ptr = p1;
            else
                ptr = (p1 < p2) ? p1 : p2;
        } else
            ptr = memchr(ptr + 1, *key, ptrlen - 1);

        if (!ptr)
            return NULL;

        ptrlen = size - (ptr - map);
    }

    return NULL;
}





char *read_key(const char *pathname, const char *key, int icase)
{
    struct stat st;
    char *map, *off, *end, *str = NULL;
    off_t size; size_t len;
    int fd, err = 0;

    fd = open(pathname, O_RDONLY);
    if (fd < 0)
        return NULL;

    if (flock(fd, LOCK_SH) < 0) {
        err = errno;
        goto close;
    }

    if (fstat(fd, &st) < 0) {
        err = errno;
        goto unlock;
    }

    size = st.st_size;

    map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (!map || map == MAP_FAILED) {
        err = errno;
        goto unlock;
    }

    len = strlen(key);
    off = find_key(map, size, key, len, icase);
    if (!off) {
        err = EILSEQ;
        goto unmap;
    }

    end = strpbrk(off, "\r\n");
    if (!end) {
        err = EILSEQ;
        goto unmap;
    }

    str = malloc(end - off - len);
    if (!str) {
        err = EILSEQ;
        goto unmap;
    }

    memset(str, 0, end - off - len);
    strncpy(str, off + len + 1, end - off - len - 1);

unmap:
    munmap(map, size);

unlock:
    flock(fd, LOCK_UN);

close:
    close(fd);
    errno = err;

    return str;
}







char *textfile_get(const char *pathname, const char *key)
{
    return read_key(pathname, key, 0);
}






int create_name(char *buf, size_t size, const char *path, const char *address, const char *name)
{
        return snprintf(buf, size, "%s/%s/%s", path, address, name);
}

static char *get_device_name(const bdaddr_t *local, const bdaddr_t *peer)
{
        char filename[PATH_MAX + 1], addr[18];

        ba2str(local, addr);
        create_name(filename, PATH_MAX, STORAGEDIR, addr, "names");

        ba2str(peer, addr);
        return textfile_get(filename, addr);
}

#endif


static void cmd_scan(int dev_id) {
    int length, flags;
    char addr[18], name[249];
    int i, n = 0;
    length = 4;    /* [1.28 *<length>]seconds [1.28*4 = 5.12] seconds */
    num_rsp = 0;
    flags = 0;
    if (dev_id < 0) {
        dev_id = hci_get_route(NULL);
        if (dev_id < 0) {
            perror("Device is not available");
            exit(1);
        }
    }
    dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("HCI device open failed");
        free(info);
        exit(1);
    }
    info = (inquiry_info *) malloc(MAX_RSP * sizeof(inquiry_info));
    bzero(info, (MAX_RSP * sizeof(inquiry_info)));
    printf("Scanning ...\n");
    for (n = 0; n < 6; n++) {
        num_rsp = hci_inquiry(dev_id, length, MAX_RSP, NULL, &info, flags);
        if (num_rsp < 0) {
            n++;
            perror("Inquiry failed");
            if (n == 5)
                exit(1);
        }
        else
            break;
    }
    rsp_val = num_rsp;
#if 0
    if (extcls || extinf || extoui)
        printf("\n");
        printf(" Num rsp %d \n",num_rsp);
//        return;
    for (i = 0; i < num_rsp; i++) {
        if (!refresh) {
            memset(name, 0, sizeof(name));
                        printf(" getting name \n");
#if 0
            tmp = get_device_name(&di.bdaddr, &(info+i)->bdaddr);
            if (tmp) {
                strncpy(name, tmp, 249);
                free(tmp);
                nc = 1;
            } else
                nc = 0;
#endif
        } else
            nc = 0;

        if (!extcls && !extinf && !extoui) {
            ba2str(&(info+i)->bdaddr, addr);

            if (nc) {
                        printf("2\n");
                printf("\t%s\t%s\n", addr, name);
                                printf("%d %d ",i++,sizeof(addr));
                continue;
            }
#endif


    printf("Devices Found = %d \n", num_rsp);
    for (i = 0; i < num_rsp; i++) {
        memset(name, 0, sizeof(name));
        printf(" getting name \n");

        ba2str(&(info + i)->bdaddr, addr);
        if (hci_read_remote_name_with_clock_offset(dd,
                                                   &(info + i)->bdaddr,
                                                   (info + i)->pscan_rep_mode,
                                                   (info + i)->clock_offset | 0x8000,
                                                   sizeof(name), name, 100000) < 0)
            strcpy(name, "n/a");
        for (n = 0; n < 248 && name[n]; n++) {
            if (!isprint(name[n]))
                name[n] = '.';
        }
        name[248] = '\0';
        memcpy(names[i], name, 249);
        printf("\t%s\t%s\n", addr, name);

        //                printf("3\n"); 
        printf("\t%s\t%s\n", addr, name);
        //	continue;

#if 0
        printf("\t%s\t%s\n", addr, name);
    ba2str(&(info+i)->bdaddr, addr);
    printf("BD Address:\t%s [mode %d, clkoffset 0x%4.4x]\n", addr,
        (info+i)->pscan_rep_mode, btohs((info+i)->clock_offset));

    if (extoui) {
        ba2oui(&(info+i)->bdaddr, oui);
    //	comp = ouitocomp(oui);
        if (comp) {
            printf("OUI company:\t%s (%s)\n", comp, oui);
            free(comp);
        }
    }

    cc = 0;

    if (extinf) {
        cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
        if (cr) {
            bacpy(&cr->bdaddr, &(info+i)->bdaddr);
            cr->type = ACL_LINK;
            if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
                handle = 0;
                cc = 1;
            } else {
                handle = htobs(cr->conn_info->handle);
                cc = 0;
            }
            free(cr);
        }

        if (cc) {
            if (hci_create_connection(dd, &(info+i)->bdaddr,
                    htobs(di.pkt_type & ACL_PTYPE_MASK),
                    (info+i)->clock_offset | 0x8000,
                    0x01, &handle, 25000) < 0) {
                handle = 0;
                cc = 0;
            }
        }
    }

    if (handle > 0 || !nc) {
        if (hci_read_remote_name_with_clock_offset(dd,
                &(info+i)->bdaddr,
                (info+i)->pscan_rep_mode,
                (info+i)->clock_offset | 0x8000,
                sizeof(name), name, 100000) < 0) {
            if (!nc)
                strcpy(name, "n/a");
        } else {
            for (n = 0; n < 248 && name[n]; n++) {
                if ((unsigned char) name[i] < 32 || name[i] == 127)
                    name[i] = '.';
            }

            name[248] = '\0';
            nc = 0;
        }
    }

    if (strlen(name) > 0)
        printf("Device name:\t%s%s\n", name, nc ? " [cached]" : "");

    if (extcls) {
        memcpy(cls, (info+i)->dev_class, 3);
        printf("Device class:\t");
        if ((cls[1] & 0x1f) > sizeof(major_classes) / sizeof(char *))
            printf("Invalid");
        else
            printf("1 Invalid");

                    printf("1\n");
        printf(" (0x%2.2x%2.2x%2.2x)\n", cls[2], cls[1], cls[0]);
    }

    if (extinf && handle > 0) {
        if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
            char *ver = lmp_vertostr(version.lmp_ver);
            printf("Manufacturer:\t%s (%d)\n",
                bt_compidtostr(version.manufacturer),
                version.manufacturer);
            printf("LMP version:\t%s (0x%x) [subver 0x%x]\n",
                ver ? ver : "n/a",
                version.lmp_ver, version.lmp_subver);
            if (ver)
                bt_free(ver);
        }

        if (hci_read_remote_features(dd, handle, features, 20000) == 0) {
            char *tmp = lmp_featurestostr(features, "\t\t", 63);
            printf("LMP features:\t0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x"
                " 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
                features[0], features[1],
                features[2], features[3],
                features[4], features[5],
                features[6], features[7]);
                    printf("3\n");
            printf("%s\n", tmp);
            bt_free(tmp);
        }

        if (cc) {
            usleep(10000);
            hci_disconnect(dd, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
        }
    }

    printf("\n");
#endif
    }

    hci_close_dev(dd);
}


int main(int argc, char *argv[]) {
    int result;
    pid = getpid();

    char cmd[50];
    if (argc < 4) {
        printf("usage: bluetoothtx [sch channel access <1 - alternating> <0 - continous>] [TA channel ] [ TA channel interval <1- cch int> <2- sch int>] \n");
        return 0;
    }
    sprintf(cmd, "/usr/local/bin/hciconfig hci0 up");
    system(cmd);

    dev_id = hci_devid("hci0");
    if (dev_id < 0) {
        perror("Invalid device");
        exit(1);
    }


    cmd_scan(dev_id);

    taarg.channel = atoi(argv[2]);
    taarg.channelinterval = atoi(argv[3]);
    printf("Filling Provider Service Table entry %d\n", buildPSTEntry(argv));
    printf("Building a WSM Request Packet %d\n", buildWSMRequestPacket());
    printf("Building a WME Application  Request %d\n", buildWMEApplicationRequest());
    printf("Builing TA request %d\n", buildWMETARequest());

    if (invokeWAVEDriver(0) < 0) {
        printf("Opening Failed.\n ");
        exit(-1);
    } else {
        printf("Driver invoked\n");

    }


    registerWMENotifIndication(receiveWME_NotifIndication);
    registerWRSSIndication(receiveWRSS_Indication);
    registertsfIndication(receiveTsfTimerIndication);

    printf("Registering provider\n ");
    if (registerProvider(pid, &entry) < 0) {
        printf("\nRegister Provider failed\n");
        removeProvider(pid, &entry);
        registerProvider(pid, &entry);
    } else {
        printf("provider registered with PSID = %u\n", entry.psid);
    }
    printf("starting TA\n");
    if (transmitTA(&tareq) < 0) {
        printf("send TA failed\n ");
    } else {
        printf("send TA successful\n");
    }
    /*if ( startWBSS ( pid, &wreq) < 0) {
        printf("\n WBSS start failed  " );
        exit (-1);
    } else {
        printf("\nWBSS started");
    }*/

    result = txWSMPPkts(pid);
    if (result = 0)
        printf("All Packets transmitted\n");
    else
        printf("%d Packets dropped\n", result);
    free(info);
    return 1;


}


int buildPSTEntry(char **argv) {

    entry.psid = 5;
    entry.priority = 1;
    entry.channel = 172;
    entry.repeatrate = 50; // repeatrate =50 per 5seconds = 1Hz
    if (atoi(argv[1]) > 1) {
        printf("channel access set default to alternating access\n");
        entry.channelaccess = CHACCESS_ALTERNATIVE;
    } else {
        entry.channelaccess = atoi(argv[1]);
    }

    return 1;
}


int buildWSMRequestPacket() {
    wsmreq.chaninfo.channel = 172;
    wsmreq.chaninfo.rate = 3;
    wsmreq.chaninfo.txpower = 15;
    wsmreq.version = 1;
    wsmreq.security = 1;
    wsmreq.psid = 5;
    wsmreq.txpriority = 1;
    memset(&wsmreq.data, 0, sizeof(WSMData));


    return 1;

}

int buildWMEApplicationRequest() {
    wreq.psid = 5;
    printf(" WME App Req %d \n", wreq.psid);
    //strncpy(wreq.acm.contents, entry.acm.contents, OCTET_MAX_LENGTH);
    //printf(" WME App Req %s \n",wreq.acm.contents);
    //wreq.acm.length = entry.acm.length;
    wreq.repeats = 1;

    wreq.persistence = 1;
    wreq.channel = 172;
    return 1;
}

int buildWMETARequest() {
    tareq.action = TA_ADD;
    tareq.repeatrate = 100;
    tareq.channel = taarg.channel;
    tareq.channelinterval = taarg.channelinterval;
    tareq.servicepriority = 1;
    return 0;
}

int txWSMPPkts(int pid) {
    int ret = 0, count = 0;
    int info_num = 0;
    char addr[18];
    /* catch control-c and kill signal*/
    signal(SIGINT, (void *) sig_int);
    signal(SIGTERM, (void *) sig_term);

    printf(" Sending packets \n");
    while (1) {
        sched_yield();
        usleep(100000);

        printf(" %d num rsp \n", num_rsp);
        if (info_num < rsp_val) {

            printf(" Bus addr num rsp %d\n", num_rsp);
            ba2str(&(info + info_num)->bdaddr, addr);
            printf(" 1 Bus addr %d \n", info_num);
            printf("\t%s\n", addr);

            memcpy(wsmreq.data.contents, addr, sizeof(addr));
            memcpy(wsmreq.data.contents + sizeof(addr), " , ", 3);

#if 0
            if (hci_read_remote_name_with_clock_offset(dd,
                                     &(info+info_num)->bdaddr,
                                     (info+info_num)->pscan_rep_mode,
                                     (info+info_num)->clock_offset | 0x8000,
                                     sizeof(name), name, 100000) < 0)
                             strcpy(name, "n/a");

                     for (n = 0; n < 248 && name[n]; n++) {
                             if ((unsigned char) name[info_num] < 32 || name[info_num] == 127)
                                     name[info_num] = '.';
                     }

                     name[248] = '\0';

#endif
            memcpy(wsmreq.data.contents + sizeof(addr) + 3, names[info_num], strlen(names[info_num]));
            printf(" Addr %s name %s %d  %d\n", addr, names[info_num], strlen(names[info_num]), sizeof(addr));
            wsmreq.data.length = sizeof(addr) + 3 + strlen(names[info_num]);
            ret = txWSMPacket(pid, &wsmreq);
            info_num++;
            if (ret < 0) {
                drops++;
            }
            else {
                packets++;
                count++;
            }
            printf("Transmitted #%llu# Dropped #%llu#\n", packets, drops);
            num_rsp = num_rsp - 1;
        }
        else {
            printf(" Info and number \n");
            num_rsp = rsp_val;
            info_num = 0;
        }
        if ((count % 20) == 0) {
            cmd_scan(dev_id);
//                    count1 = 0;
        }
    }
    printf("\n Transmitted =  %d dropped = %llu\n", count, drops);
    //cancelReq.aci = 0;
    //cancelReq.channel = 172;
    //cancelTX ( pid, &cancelReq);
    return drops;
}

void receiveWME_NotifIndication(WMENotificationIndication *wmeindication) {
}

void receiveWRSS_Indication(WMEWRSSRequestIndication *wrssindication) {

    printf("WRSS recv channel %d", (u_int8_t) wrssindication->wrssreport.channel);
    printf("WRSS recv reportt %d", (u_int8_t) wrssindication->wrssreport.wrss);

}


void receiveTsfTimerIndication(TSFTimer *timer) {
    printf("TSF Timer: Result=%d, Timer=%d", (u_int8_t) timer->result, (u_int64_t) timer->timer);
}

int confirmBeforeJoin(u_int8_t psid) {
    printf("Link Confirmed PSID=%d\n", (u_int8_t) psid);
    return 0;
}

void sig_int(void) {
    int ret;
    char cmd[50], cmd1[50];

    free(info);
    ret = stopWBSS(pid, &wreq);
    removeProvider(pid, &entry);
    sprintf(cmd, "/usr/local/bin/hciconfig hci0 down");
    system(cmd);
    sprintf(cmd1, "/usr/local/bin/hciconfig hci0 up");
    system(cmd1);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("Packets Dropped = %llu\n", drops);
    printf("bluetoothtx killed by control-C\n");
    exit(0);

}

void sig_term(void) {
    int ret;
    char cmd[50], cmd1[50];

    free(info);
    ret = stopWBSS(pid, &wreq);
    removeProvider(pid, &entry);
    sprintf(cmd, "/usr/local/bin/hciconfig hci0 down");
    system(cmd);
    sprintf(cmd1, "/usr/local/bin/hciconfig hci0 up");
    system(cmd1);
    signal(SIGINT, SIG_DFL);
    printf("\n\nPackets Sent =  %llu\n", packets);
    printf("\nPackets Dropped = %llu\n", drops);
    printf("bluetoothtx killed by control-C\n");
    exit(0);
}

	
