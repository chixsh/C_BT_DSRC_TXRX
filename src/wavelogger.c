/*

* Copyright (c) 2005-2007 Arada Syatems, Inc. All rights reserved.

* Proprietary and Confidential Material.

*

*/

#include "wave.h"
#include "wavelogger.h"
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "queue.h"
#include <pthread.h>
#include "os.h"
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syslog.h>


/*Use xstr to stringise the macro argument*/
#define xstr(x) str(x)
#define str(x) #x

#define MILLION 1000000

#ifndef LOCOMATE_FILESZ
#define LOCOMATE_FILESZ  405550U
#endif
unsigned int seq_num = 1;
/**************************************************************************************/
uint8_t new_rate_set[] = {0, 6, 9, 12, 18, 24, 36, 48, 54, 72, 96, 108};
struct pcap_file_header pcaphdr;
struct pcap_pkthdr pcap_pkt_hdr;
static int first_time = 1;
static char ap_name[5];
unsigned char hwa[IEEE80211_ADDR_LEN];

uint32_t mod_depl_dev_id;
uint32_t file_psid;
static int pktbufcnt = 0;
//char *buflogfile = "/tmp/pcap_tmp.log";
int buflogfd = 0;
static int log_to_usb = 0;
static int log_utc = 0;
static int log_local = 0;
#define MAX_PCAP_PKT 1400
char logsyscmd[100];
#define TX_PACKET 1
#define RX_PACKET 2
/**************************************************************************************/
static char logfilename[100];
static char hrlogfilename[100];
static char oldhrlogfilename[100];
//static FILE *logfile;
static uint16_t logport = 23456;
/*NOTE*/
static struct sockaddr_in logip;
static pthread_t loggingthread;
static WSMIndication wsmind;
static GPSData gpsdata;
static additionalWSMP ni;
struct src_loss_table srcLossTable;
unsigned char buffer[2048];

static int fileOpen = 0;
static uint8_t loggingmode = 1;
static int req_sent = 0;
static uint8_t loggingFormat = 0;
static int wrfd = 0;
static int inprogress = 0;
static uint64_t interPacketDelay;
static float tolerance = 1.3;

void fill_pcaphdr(void);

int write_to_logfile();

#ifdef LOCOMATE_FILELIMIT
static uint32_t bytesWritten = 0;
#endif

extern int parseGPSBinData(GPSData *gps, char *str, int len);

extern int isBigEndian();

#define DATA_RATE 116
#define IS_TX 128
#define CHANNEL_NUMBER 56
#define MB 1048576
static uint32_t total_length = 0;
uint32_t max_file_size = 10;

static pthread_t logthread;
uint8_t prism_hdr[] = {
        0x44, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00,
        0x61, 0x74, 0x68, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x23, 0x86, 0xe5, 0x2a, 0x44, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x04, 0x00, 0xb4, 0xd5, 0xe5, 0x59, 0x44, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
        0xac, 0x00, 0x00, 0x00, 0x44, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x0a, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x35, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x26, 0xad, 0x03, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0xdc};


/**********circular buffer related functions **************/
circbuflog cb_log;

int cblogIsFull(circbuflog *cb) {
    return (cb->end + 1) % cb->size == cb->start;
}

int cblogIsEmpty(circbuflog *cb) {
    return cb->end == cb->start;
}

inline void cblogwritetofile() {
    int ret;
    uint16_t len = 0;
    char *pktdata = NULL;
    //cb_read
    len = cb_log.entries[cb_log.start].length;
    pktdata = cb_log.entries[cb_log.start].data;
    ret = write_filelogentry(pktdata, len);
    cb_log.start = (cb_log.start + 1) % cb_log.size;
    if (ret == FILE_SIZE_EXCEDDED)
        printf("[LOGGING: FILE SIZE EXCEDDED]\n");
}

/************************************************************/
void *log_thread_f(void *data) {
    //logthreadcreated =1;
    while (1) {
        while (!cblogIsEmpty(&cb_log)) {
            cblogwritetofile();
            sched_yield();
        }
        usleep(200000);
        // sleep(1);
    }

}

uint8_t hash_src(char *src) {
    uint16_t sum = 0;
    uint8_t i;

    for (i = 0; i < MACADDRSIZE; i++)
        sum = sum + src[i];
    return sum % HASHSIZE;
}

void
list_src(void) {
    struct entry *ntry;
    int hash;

    for (hash = 0; hash < HASHSIZE; hash++) {
        LIST_FOREACH(ntry, &srcLossTable.st_hash[hash], si_hash)
        {
            printf("\nSrc MAC Addr      = %s \n", ntry->src);
            printf("Start Packets No. = %llu \n", ntry->startPacketNo);
            printf("Last Packet No.   = %llu \n", ntry->lastSeqNoRcvd);
            printf("Lost Packets      = %u \n", ntry->lostPackets);
            printf("Late Packets      = %u \n", ntry->latePackets);
            printf("Total Packets     = %llu \n\n", ntry->totalPackets);
            printf("Out of Order Packets     = %llu \n\n", ntry->outOfOrderPackets);
        }
    }
}


struct entry *
find_src(char *src, uint64_t totalpackets, long sec, long usec) {
    struct entry *ntry;
    uint8_t hash;
//	int ret;
    int diff = 0;
    uint64_t timediff = 0;

    hash = hash_src(src);
    LIST_FOREACH(ntry, &srcLossTable.st_hash[hash], si_hash)
    {
        if (!(strcmp(ntry->src, src))) {
            ntry->totalPackets++;
            diff = totalpackets - ntry->lastSeqNoRcvd;
            ntry->lastSeqNoRcvd = totalpackets;
            if (diff > 1) {
                diff--;
                ntry->lostPackets += diff;
            }
            if (diff < 0) {
                ntry->outOfOrderPackets++;
            }
            timediff = (sec - ntry->sec) * 1000000 + (usec - ntry->usec);

            if (timediff > (uint64_t)(tolerance *
                                      #ifdef WIN32
                                      (__int64)
                                      #endif
                                      interPacketDelay))
                ntry->latePackets++;
            ntry->sec = sec;
            ntry->usec = usec;
            return ntry;
        }
    }
    return NULL;
}

struct entry *
add_src(char *src, int totalpackets, long sec, long usec) {
    struct entry *ntry;
    uint8_t hash;
    //int i;

    ntry = (struct entry *) malloc(sizeof(struct entry));
    ntry->lostPackets = 0;
    ntry->latePackets = 0;
    ntry->totalPackets = 1;
    ntry->startPacketNo = totalpackets;
    ntry->lastSeqNoRcvd = totalpackets;
    ntry->sec = sec;
    ntry->usec = usec;
    strncpy(ntry->src, src, MACADDRSIZE + 1);
    printf("[WAVELOGGER:Found new source,MAC= %s]\n", ntry->src);
    hash = hash_src(src);
    //TAILQ_INSERT_TAIL(&srcLossTable.st_user, ntry, si_list);
    //LIST_INSERT_HEAD(&srcLossTable.st_hash[hash], ntry, si_hash);
    return ntry;
}

void *logging_client(void *data);

/*
int build_gps_logentry(uint8_t logtype, char *buf, WSMIndication *wsm, additionalWSMP *nodeinfo, GPSData *gps, int gpscontents);
int build_gps_csventry(uint8_t logtype, char *buf, WSMIndication *wsm, additionalWSMP *nodeinfo, GPSData *gps, int gpscontents);
int build_gps_xmlentry(uint8_t logtype, char *buf, WSMIndication *wsm, additionalWSMP *nodeinfo, GPSData *gps, int gpscontents);
*/

const char *
_mac_sprintf(const u_int8_t *mac) {
    static char etherbuf[18];
    snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return etherbuf;
}

void request_sent() {
    req_sent = 1;
}


void request_rcvd() {
    req_sent = 1;
}

int isRequestPending() {
    return req_sent;
}


char *get_logfile() {
    return logfilename;
}

void set_logfile(char *filename) {
    if (filename == NULL) {
        log_utc = 1;
        //sprintf(logfilename, "/etc/wsmpackets.log");
        //return;
    }
    else {
        sprintf(logfilename, "%s", filename);
        if ((strstr(logfilename, "usb/")) != NULL)
            log_to_usb = 1;
        else
            log_local = 1;
    }
}

void genhrlogfilename(char *ctimestr, char *hrlogfile) {
    char *token = NULL;
    char *str = NULL;
    static int check_min = 0, first_filedone = 0;
    int i;
    int month_num = 0, date, hour, min, year;
    char *month;
    char mon[12][4] = {{"Jan\0"},
                       {"Feb\0"},
                       {"Mar\0"},
                       {"Apr\0"},
                       {"May\0"},
                       {"Jun\0"},
                       {"Jul\0"},
                       {"Aug\0"},
                       {"Sep\0"},
                       {"Oct\0"},
                       {"Nov\0"},
                       {"Dec\0"}
    };

    str = ctimestr;

    token = strtok(str, " ");        //week_day

    token = strtok(NULL, " ");        //month
    month = token;
    for (i = 1; i <= 12; i++) {
        if (!strcmp(mon[i - 1], month))
            month_num = i;
    }

    token = strtok(NULL, " ");        //date
    date = atoi(token);

    token = strtok(NULL, ":");        //hour
    hour = atoi(token);

    token = strtok(NULL, ":");        //min
    min = atoi(token);

    token = strtok(NULL, " ");        //sec

    token = strtok(NULL, " ");        //year
    year = atoi(token);

    if (first_filedone) {
        // Now we have New file based on size so we need to change the Filename even if next 10min slot has not arrived
        //if(((min/10)*10) != check_min){
        seq_num++;
        if (seq_num == 10000)
            seq_num = 1;
        //}
    }
    sprintf(hrlogfile, "%04d%02d%02d_%02d%02d_%x_%04x_%s_%04d", year, month_num, date, hour, (min / 10) * 10, file_psid,
            mod_depl_dev_id, ap_name, seq_num);
    first_filedone = 1;
    check_min = (min / 10) * 10;
    /*Suffix filename with format*/
    if (loggingFormat == XML) {
        strcat(hrlogfile, ".xml");
    }
    else if (loggingFormat == CSV) {
        strcat(hrlogfile, ".csv");
    }
    else if (loggingFormat == PCAP) {
        strcat(hrlogfile, ".pcap");
    }
    else if (loggingFormat == PCAPHDR) {
        strcat(hrlogfile, ".pcaphdr");
    } else {
        loggingFormat = PCAP;
        //     printf("[LOG: Logformat %s not supported. Using default format]\n"/*, optarg*/);
    }
    //printf("Hour log file %s\n", hrlogfile);
}


int open_log(uint32_t psid) {
    struct timeval tv;
    char hrlogfile[100];
    //time_t tme;
    char *str, ctimestr[50], ap[20];
    int write_pcap_hdr = 0, ret = 0;
    FILE *file_size, *apname;
    char temp_buf[50], temp_str[50];

    file_psid = psid;
    if (fileOpen) {
        return wrfd;
    }

    if (first_time)
        printf("[WAVELOGGER: Started logging]\n");

    if (first_time) {
        apname = popen("grep -i apname /var/config", "r");
        if (apname != NULL) {
            fgets(temp_buf, 50, apname);
            sscanf(temp_buf, "%s %s", temp_str, ap);
            pclose(apname);
        }
        ret = strlen(ap);
        if (ret <= 4) {
            sprintf(ap_name, "%s", ap);
        }
        else if (ret > 4) {
            sprintf(ap_name, "%c%c%c%c", ap[ret - 4], ap[ret - 3], ap[ret - 2], ap[ret - 1]);
        }
    }

    if (log_to_usb || log_utc) {
        gettimeofday(&tv, NULL);
        str = ctime(&tv.tv_sec);
        strcpy(ctimestr, str);
        //printf("ctimestr %s\n", ctimestr);
        genhrlogfilename(ctimestr, hrlogfile);
        strcpy(hrlogfilename, "/tmp/usb/ModelDeploymentPktCaptures/"/*logfilename*/);
        if (first_time) {
            first_time = 0;
            //initialize logging circular buffer
            cb_log.size = CBLOGSZ + 1;
            cb_log.start = 0;
            cb_log.end = 0;
            cb_log.entries = (logpacket *) calloc(cb_log.size, sizeof(logpacket));
            pthread_create(&logthread, NULL, log_thread_f, NULL);
            sched_yield();
            sprintf(logsyscmd, "mkdir -p %s", hrlogfilename);
            if (system(logsyscmd) < 0) {
                (void) syslog(LOG_INFO, "Err: %s (%d)\n", logsyscmd, errno);
                return -1;
            }
            file_size = popen("grep -i radio-logfilesize /var/config", "r");
            if (file_size != NULL) {
                memset(temp_buf, 0, sizeof(temp_buf));
                fgets(temp_buf, 100, file_size);
                sscanf(temp_buf, "%s %d", temp_str, &max_file_size);
                pclose(file_size);
            }

        }

        strcat(hrlogfilename, hrlogfile);
        //printf("Open file %s\n", hrlogfilename);
        wrfd = open(hrlogfilename, O_WRONLY | O_APPEND, S_IRWXU | S_IRWXO | S_IRWXG);
        if (wrfd < 0) {
            /* write the pcap header for pcap & pcaphdr format for every new file */
            if ((loggingFormat == PCAP) || (loggingFormat == PCAPHDR))
                write_pcap_hdr = 1;
            wrfd = open(hrlogfilename, O_WRONLY | O_CREAT | O_APPEND, S_IRWXU | S_IRWXO | S_IRWXG);

            /*Add Root Element for XML files*/
            if (loggingFormat == XML)
                write(wrfd, "\n<XMLLOG> \n", strlen("\n<XMLLOG> \n"));
#if 0 // we are not using oldhrlogfilename now in the new thread implementation
            if(log_to_usb)
            {
                if(oldhrlogfilename[0] != '\0')
                {
                    sprintf(logsyscmd, "rm -f %s", oldhrlogfilename);
                    if(system(logsyscmd)<0) {
                        (void)syslog(LOG_INFO,"Err: %s (%d)\n",logsyscmd, errno);
                        return -1;
                    }

                }
            }
#endif
            (void) syslog(LOG_INFO, "opening %s file \n", hrlogfilename);
            if (wrfd <= 0) {
                printf("ERROR : opening %s file \n", hrlogfilename);
                return -1;
            }
            else
                fileOpen = 1;
        } else if (wrfd)
            fileOpen = 1;

        if (write_pcap_hdr) {
            // fill pcap hdr
            fill_pcaphdr();
            memcpy(buffer, &pcaphdr, sizeof(pcaphdr));
            ret = write_filelogentry((char *) buffer, sizeof(pcaphdr));
            if (ret == FILE_SIZE_EXCEDDED)
                printf("[LOGGING: FILE SIZE EXCEDDED]\n");
        }
        return wrfd;
    }
    else if (log_local) {
        /*Suffix filename with format*/
        if (loggingFormat == XML) {
            strcat(logfilename, ".xml");
        }
        else if (loggingFormat == CSV) {
            strcat(logfilename, ".csv");
        }
        else if (loggingFormat == PCAP) {
            strcat(logfilename, ".pcap");
        }

        wrfd = open(logfilename, O_WRONLY | O_APPEND, S_IRWXU | S_IRWXO | S_IRWXG);
        if (wrfd < 0) {
            wrfd = open(logfilename, O_WRONLY | O_CREAT | O_APPEND, S_IRWXU | S_IRWXO | S_IRWXG);
            if (wrfd < 0) {
                printf("Opening file %s failed....\n", logfilename);
                return -1;
            }
            else if (wrfd)
                fileOpen = 1;
        }
            //logfile = fopen(logfilename, "wb");

        else
            fileOpen = 1;



        /*Add Root Element for XML files*/
        if (loggingFormat == XML) {
            write(wrfd, "<XMLLOG> \n", strlen("<XMLLOG> \n"));
        }

        return wrfd;
    }
    return 0;
}


int close_log(int remove_pcap) {
    int ret = 0;
    if (remove_pcap) {
        while (!cblogIsEmpty(&cb_log))
            cblogwritetofile();
        free(cb_log.entries);
        pthread_cancel(logthread);
    }
    if (!fileOpen) {
        return -1;
    }
    /*Wait until an entry is written*/
    if (inprogress) {
        if (errno == EINTR)
            (void) syslog(LOG_INFO, "wavelogger:: write entry to %s interrrupted\n", hrlogfilename);
    }

    /*Close Root element for XML files*/
    if (loggingFormat == XML) {
        write(wrfd, "\n </XMLLOG> \n", strlen("\n</XMLLOG> \n"));
    }

    ret = close(wrfd);
#if 0
    if(log_to_usb)
        write_to_logfile();

    if(remove_pcap){
        sprintf(logsyscmd, "rm -f %s", oldhrlogfilename);
        if(system(logsyscmd)<0) {
            (void)syslog(LOG_INFO,"Err: %s (%d)\n",logsyscmd, errno);
            return -1;
         }
    }
#endif
    if (ret == 0)
        fileOpen = 0;
    else {
        printf("[WAVELOGGER: Error==> Could not close file %s, Quitting]\n", hrlogfilename);
        return -1;
    }
    return 0;
}

//This function is not used as we are directly writing to USB

int write_to_logfile() {
    int ret = 0;
    int copy_ret = 0;
    char capture_dir[] = "ModelDeploymentPktCaptures/";
#if 0
    sprintf(logsyscmd,"mount -t vfat /dev/sda1 %s",logfilename);
    if(system(logsyscmd)<0) {
        (void)syslog(LOG_INFO,"Err: %s (%d)\n",logsyscmd, errno);
        return -1;
    }

    if(first_time)
    {
    sprintf(logsyscmd,"mkdir -p %s%s",logfilename, capture_dir);
        if(system(logsyscmd)<0) {
        (void)syslog(LOG_INFO,"Err: %s (%d)\n",logsyscmd, errno);
            return -1;
        }

    }
    first_time = 0;
#endif

    strcpy(oldhrlogfilename, hrlogfilename);
    sprintf(logsyscmd, "cp -f %s %s%s", hrlogfilename, logfilename, capture_dir);
    copy_ret = system(logsyscmd);
    if ((WIFEXITED(copy_ret)) && (WEXITSTATUS(copy_ret) != 0)) {
        (void) syslog(LOG_INFO, "Err: %s (%d)\n", logsyscmd, errno);
        return -1;
    }


    //ret = umount(logfilename);
#if 0
    sprintf(logsyscmd, "umount /dev/sda1\n");
  if(system(logsyscmd)<0) {
      (void)syslog(LOG_INFO,"Err: %s (%d)\n",logsyscmd, errno);
      return -1;
  }
#endif


    return ret;
}

int write_filelogentry(char *logentry, int len) {
    static int inuse = 0;

#if 0
    if(log_to_usb && first_time)
    {
        sprintf(logsyscmd,"mkdir -p %s", logfilename);
        if(system(logsyscmd)<0) {
            (void)syslog(LOG_INFO,"Err: %s (%d)\n",logsyscmd, errno);
            return -1;
        }

        memset(oldhrlogfilename, 0, sizeof(oldhrlogfilename));
    }
#endif

    pktbufcnt++;
#ifdef LOCOMATE_FILELIMIT
    bytesWritten += len;
    if ( bytesWritten >  LOCOMATE_FILESZ ) {
        printf("[WAVELOGGER: Error==> FILE SIZE LIMIT EXCEDDED %u Bytes]\n", LOCOMATE_FILESZ);
        printf("[WAVELOGGER: Logging stopped, Restart Application to LOG again]\n");
        close_log(0);
        return FILE_SIZE_EXCEDDED;
    }
#endif
    while (inuse);
    inuse = 1;
    inprogress = 1;

    write(wrfd, logentry, len);
    inuse = 0;
    inprogress = 0;

    total_length += len;
//	if((pktbufcnt == MAX_PCAP_PKT) && (log_to_usb || log_utc))
    if ((total_length >= (max_file_size * MB)) && (log_to_usb || log_utc)) {
        pktbufcnt = 0;
        total_length = 0;
        close_log(0);
        //system("sync; echo 3 > /proc/sys/vm/drop_caches");
        system("sync");
        open_log(file_psid);
    }
    return len;
}

int write_logentry(char *logentry, int len) {
    if (!cblogIsFull(&cb_log)) {
        //cbwrite
        cb_log.entries[cb_log.end].length = len;
        memcpy(cb_log.entries[cb_log.end].data, logentry, len);
        cb_log.end = (cb_log.end + 1) % cb_log.size;
    }
    else
        syslog(LOG_INFO, "LOGGING CB_FULL");
}

void set_logging_mode(uint8_t mode) {
    loggingmode = mode;
}

void set_logging_addr(struct sockaddr_in ip, uint16_t port) {
    logip = ip;
    logport = port;
}

void set_logging_format(uint8_t format) {
    /*Can't change format once the file is open*/
    if (fileOpen)
        return;
    if (format > PCAP)
        return;
    loggingFormat = format;
}

void set_packet_delay(uint64_t packetDelay) {
    interPacketDelay = packetDelay;
}

void start_logging() {
    pthread_create(&loggingthread, NULL, logging_client, NULL);
}

void stop_logging() {
    printf("[WAVELOGGER: Stopped Logging]\n");
#ifndef    WIN32
    //pthread_kill_other_threads_np();
#endif
}

void fill_pcaphdr(void) {
    pcaphdr.magic = 0xa1b2c3d4;
    pcaphdr.version_major = 0x0002;
    pcaphdr.version_minor = 0x0004;
    pcaphdr.thiszone = 0x00;
    pcaphdr.sigfigs = 0x00;
    pcaphdr.snaplen = 0xffff;
    pcaphdr.linktype = 0x0077;
}

void new_wme_swapGenericData(int size, void *data) {
    switch (size) {
        case 2:
            *(uint16_t *) data = swap16(*(uint16_t *) data);
            break;

        case 4:
            *(uint32_t *) data = swap32(*(uint32_t *) data);
            break;

        case 8:
            *(uint64_t *) data = swap64(*(uint64_t *) data);
            break;

    }
}

uint32_t new_putPsidbyLen(uint8_t *addr, uint32_t psid, int *retIdx) {
    uint32_t retPsid = 0;
    retPsid = *(uint32_t *) addr;
    if (psid <= 0x7F) {
        *retIdx = 1;
    }
    else if (psid >= 0x8000 && psid <= 0xBFFF) {
        *retIdx = 2;
        retPsid = ((retPsid & 0x00ff0000) << 8) | ((retPsid & 0xff000000) >> 8);
    }
    else if (psid >= 0xC00000 && psid <= 0xDFFFFF) {
        *retIdx = 3;
        retPsid = ((retPsid & 0x0000ff00) << 16) | ((retPsid & 0xff000000) >> 16) | ((retPsid & 0x00ff0000));
    }
    else if (psid >= 0xE0000000 && psid <= 0xEFFFFFFF) {
        *retIdx = 4;
        retPsid = ((retPsid & 0x000000ff) << 24) | ((retPsid & 0x0000ff00) << 8) | ((retPsid & 0x00ff0000) >> 8) |
                  ((retPsid & 0xff000000) >> 24);
    }
    if (!BIGENDIAN)
        retPsid = htobe32(retPsid);
    return retPsid;
}

int local_logging_client(int from_txrx, void *buf, double time, int usec, int capture_complete_packet, char *buff) {
    int len;
    uint16_t txlen = 0, rxlen = 0;
    int i = 0, j = 0/*,capture_complete_packet = 0*/;
    pcap_pkt_hdr.ts.tv_sec = time;
    pcap_pkt_hdr.ts.tv_usec = usec;
    WSMHDR wsmhdr;
    uint32_t psidLen = 0;
    WSMRequest *wsmreq = NULL;
    WSMIndication *wsmind = NULL;
    if (from_txrx & TX_PACKET)               //called from tx_client
    {
        prism_hdr[IS_TX] = TX_PACKET;
        wsmreq = (WSMRequest *) buf;
        wsmhdr.version = wsmreq->version;
        wsmhdr.psid = wsmreq->psid;
        memcpy(wsmhdr.macaddr, wsmreq->srcmacaddr, sizeof(wsmhdr.macaddr));
        wsmhdr.chaninfo.channel = wsmreq->chaninfo.channel;
        wsmhdr.chaninfo.rate = wsmreq->chaninfo.rate;
        wsmhdr.chaninfo.txpower = wsmreq->chaninfo.txpower;
    }
    else if (from_txrx & RX_PACKET) //called from rx_client
    {
        prism_hdr[IS_TX] = RX_PACKET;
        wsmind = (WSMIndication *) buf;
        wsmhdr.version = wsmind->version;
        wsmhdr.psid = wsmind->psid;
        memcpy(wsmhdr.macaddr, wsmind->macaddr, sizeof(wsmhdr.macaddr));
        wsmhdr.chaninfo.channel = wsmind->chaninfo.channel;
        wsmhdr.chaninfo.rate = wsmind->chaninfo.rate;
        wsmhdr.chaninfo.txpower = wsmind->chaninfo.txpower;
    }
    //getMACAddr(hwa, wsmhdr->chaninfo.channel);
    for (j = 0; j < IEEE80211_ADDR_LEN; j++) {
        prism_hdr[154 + j] = wsmhdr.macaddr[j];
    }
    prism_hdr[DATA_RATE] = new_rate_set[wsmhdr.chaninfo.rate];
    prism_hdr[CHANNEL_NUMBER] = wsmhdr.chaninfo.channel;
    //memcpy(buff + i, &pcap_pkt_hdr, sizeof(pcap_pkt_hdr));
    i += sizeof(pcap_pkt_hdr);

    if (capture_complete_packet) {
        memcpy(buff + i, &prism_hdr, sizeof(prism_hdr));
        i += sizeof(prism_hdr);
        memcpy(buff + i, &wsmhdr.version, 1);        //version
        i += 1;

        if (from_txrx & TX_PACKET) {
            new_wme_swapGenericData(sizeof(wsmhdr.psid), &(wsmhdr.psid));
            wsmhdr.psid = new_putPsidbyLen((uint8_t * ) & (wsmhdr.psid), wsmreq->psid, (int *) &psidLen);
            memcpy(buff + i, &wsmhdr.psid, psidLen);
            i += psidLen;
        }
        else if (from_txrx & RX_PACKET) {
            new_wme_swapGenericData(sizeof(wsmhdr.psid), &(wsmhdr.psid));
            wsmhdr.psid = new_putPsidbyLen((uint8_t * ) & (wsmhdr.psid), wsmind->psid, (int *) &psidLen);
            memcpy(buff + i, &wsmhdr.psid, psidLen);
            i += psidLen;
        }

        *(buff + i) = 15;            //elemnt-id
        i += 1;

        *(buff + i) = 1;            //length
        i += 1;

        memcpy(buff + i, &wsmhdr.chaninfo.channel, 1);    //channel
        i += 1;

        *(buff + i) = 16;            //element-id
        i += 1;

        *(buff + i) = 1;            //length
        i += 1;

        memcpy(buff + i, &new_rate_set[wsmhdr.chaninfo.rate], 1);    //rate
        i += 1;

        *(buff + i) = 4;            //element-id
        i += 1;

        *(buff + i) = 1;            //length
        i += 1;

        memcpy(buff + i, &wsmhdr.chaninfo.txpower, 1);    //txpower
        i += 1;

        *(buff + i) = 0x80;            //element-id
        i += 1;

        if (from_txrx & TX_PACKET)               //called from tx_client
        {
            txlen = wsmreq->data.length;
            if (!BIGENDIAN)
                txlen = htobe16(txlen);
            memcpy(buff + i, &txlen, 2);    //WSMData length
            i += 2;

            memcpy(buff + i, &wsmreq->data.contents, wsmreq->data.length);   //WSMData contents
            i += wsmreq->data.length;
        }
        else if (from_txrx & RX_PACKET) //called from rx_client
        {
            rxlen = wsmind->data.length;
            if (!BIGENDIAN)
                rxlen = htobe16(rxlen);
            memcpy(buff + i, &rxlen, 2);    //WSMData length
            i += 2;

            memcpy(buff + i, &wsmind->data.contents, wsmind->data.length);   //WSMData contents
            i += wsmind->data.length;
        }
    }
    pcap_pkt_hdr.caplen = i - sizeof(pcap_pkt_hdr);
    pcap_pkt_hdr.len = i - sizeof(pcap_pkt_hdr);
    memcpy(buff, &pcap_pkt_hdr, sizeof(pcap_pkt_hdr));

    len = i;
    if (fileOpen) {
    }
    else
        printf("[WAVELOGGER: Error==> No log files open, could not write]\n");
    return len;
}

void *logging_client(void *data) {
    int clsock;
    int len, ret;
    socklen_t lenfrom;
//	uint16_t port=0;
    //char str[INET6_ADDRSTRLEN];
    static unsigned char buf[2048];
    struct sockaddr_in client;
    struct sockaddr_in from;

    WIN_SOCK_DLL_INVOKE

            clsock = socket(AF_INET, SOCK_DGRAM, 0);

    if (clsock < 0)
        perror("SOCK");

    client.sin_family = AF_INET;
    client.sin_addr.s_addr = logip.sin_addr.s_addr;
    client.sin_port = htons(logport);
    len = lenfrom = sizeof(struct sockaddr_in);
    if (bind(clsock, (struct sockaddr *) &client, len) < 0) {
        perror("bind() failed");
        return NULL;
    }

    lenfrom = sizeof(struct sockaddr_in);
    /*Must call set_logging_format from the APP before doing a start_logging or open_log*/
    sprintf(buf, "[WAVELOGGER: Started IP_UDP logging on %s:%u]\n", inet_ntoa(logip.sin_addr), logport);
    printf("%s\n", buf);
    while (1) {
        request_sent();
        len = recvfrom(clsock, buf, 1024, 0, (struct sockaddr *) &from, &lenfrom);
        request_rcvd();
        memcpy(&ni.packetnum, buf, 4);
        memcpy(&ni.rssi, buf + 4, 1);
        memcpy(ni.macaddr, buf + 5, 6);
        memcpy(wsmind.data.contents, buf + 11, len - 11);
        wsmind.data.length = len - 11;
        parseGPSBinData(&gpsdata, wsmind.data.contents, wsmind.data.length);
        len = build_gps_logentry(loggingmode, buf, &wsmind, &ni, &gpsdata, get_gps_contents());

        if (fileOpen) {
            ret = write_filelogentry(buf, len);
            if (ret == FILE_SIZE_EXCEDDED)
                printf("[LOGGING: FILE SIZE EXCEDDED]\n");
        }
        else
            printf("[WAVELOGGER: Error==> No log files open, could not write]\n");
    }
}



/*logtype: 0==>WSMP, 1==>GPSUDP, 2==>GPSIP 3==>GPSIPUDP 4==>GPSTXLOCAL*/
/*pass NULL in GPSData to write an entry for a  normal WSM packet*/
int build_gps_logentry(uint8_t logtype, char *buf, WSMIndication *wsm, additionalWSMP *nodeinfo, GPSData *gps,
                       int gpscontents) {
    static int seq = 0;
    static int inuse = 0;
    int ret = 0;
    int i = 0;
    struct timeval tv;
    char m[150];
    struct channelInfo ci;
    //float tempf = 0.0f;
    char lastsrc[20];
    //static long sec =  0;
    //static long usec = 0;
    //static long diff = 0;
    if (loggingFormat == 1)
        return build_gps_xmlentry(logtype, buf, wsm, nodeinfo, gps, gpscontents);
    else if (loggingFormat == 2)
        return build_gps_csventry(logtype, buf, wsm, nodeinfo, gps, gpscontents);

    while (inuse);
    inuse = 1;

    if ((buf == NULL) || (wsm == NULL)) {
        inuse = 0;
        return -1;
    }
    memcpy(&ci, &wsm->chaninfo, sizeof(ci));
    seq++;
    sprintf(buf + i, "[BEGIN] ");
    i += 8;

    sprintf(m, "<seq=%d> ", seq);
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));
    gettimeofday(&tv, NULL);
#ifndef WIN32
    sprintf(m, "<logtime seconds=%llu microseconds=%d> ", (uint64_t) tv.tv_sec, (uint32_t) tv.tv_usec);
#else
    sprintf(m, "<logtime seconds=%llu microseconds=%d> ", tv.tv_sec, tv.tv_usec);
#endif
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    sprintf(m, "<src=%s> ", (nodeinfo == NULL) ? _mac_sprintf(wsm->macaddr) : _mac_sprintf(nodeinfo->macaddr));
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    switch (logtype) {
        case 0:
            sprintf(m, "<packet=%s> ", (gps == NULL) ? "wsmp" : "gps_wsmp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<pcid=%d> ", wsm->psid);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<ver=%u> <sec=%u> ", wsm->version, wsm->security);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<channel=%u> <rateindex=%u> <txpower=%u> ", ci.channel, ci.rate, ci.txpower);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<data=");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            if (gps) {
                memcpy(buf + i, "GPSDATA", 7);
                i += (7);
            } else {
                memcpy(buf + i, wsm->data.contents, wsm->data.length);
                i += (wsm->data.length);
            }
            sprintf(m, "> ");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));

            break;

        case 1:
            sprintf(m, "<packet_type=%s> ", "gps_udp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 2:
            sprintf(m, "<packet_type=%s> ", "gps_ip");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 3:
            sprintf(m, "<packet_type=%s> ", "gps_ip_udp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 4:
            sprintf(m, "<packet_type=%s> ", "gps_tx_local");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;
    }
    if (nodeinfo) {
        ret = nodeinfo->packetnum;
        if (isBigEndian())
            ret = swap32_(nodeinfo->packetnum);
        sprintf(m, "<packetnum=%u> <rssi=%u> ", ret, nodeinfo->rssi);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
        sprintf(lastsrc, "%s", (nodeinfo == NULL) ? _mac_sprintf(wsm->macaddr) : _mac_sprintf(nodeinfo->macaddr));
        if (logtype != 4) {
            if (find_src(lastsrc, ret, tv.tv_sec, tv.tv_usec) == NULL) {
                add_src(lastsrc, ret, tv.tv_sec, tv.tv_usec);
            }
        }
    }

    if (gps) {
        if (gpscontents & GPS_STG) {
            sprintf(m, "<gpsstring=");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            if (logtype != 0) {
                for (ret = 0; ret < wsm->data.length; ret++)
                    buf[i + ret] = wsm->data.contents[ret];
                i += (wsm->data.length);
            } else {
                for (ret = 11; ret < wsm->data.length; ret++)
                    buf[i + ret - 11] = wsm->data.contents[ret];
                i += (wsm->data.length - 11);
            }
            sprintf(m, "> ");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_TIM) {
            sprintf(m, "<gpstime=%lf> ", gps->time);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_LAT) {
            sprintf(m, "<latitude=%lf %c> ", gps->latitude, (gps->latitude < 0) ? 'S' : 'N');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_LON) {
            sprintf(m, "<longitude=%lf %c> ", gps->longitude, (gps->longitude < 0) ? 'W' : 'E');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_ALT) {
            sprintf(m, "<altitude=%lf> ", gps->altitude);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_SPD) {
            sprintf(m, "<speed=%lf> ", gps->speed);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_DIR) {
            sprintf(m, "<direction=%lf> ", gps->course);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_HDP) {
            sprintf(m, "<hdop=%lf> ", gps->hdop);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_VDP) {
            sprintf(m, "<vdop=%lf> ", gps->vdop);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_HEE) {
            sprintf(m, "<hee=%lf> ", gps->hee);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_VEE) {
            sprintf(m, "<vee=%lf> ", gps->vee);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_NSV) {
            sprintf(m, "<nsv=%u> ", gps->numsats);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_FIX) {
            sprintf(m, "<fix=%u> ", gps->fix);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_TOW) {
            sprintf(m, "<tow=%lf> ", gps->tow);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
    }
    sprintf(buf + i, "[END]");
    i += 5;
    inuse = 0;
    return i;
}

/*logtype: 0==>WSMP, 1==>GPSUDP, 2==>GPSIP*/
/*pass NULL in GPSData to write an entry for a  normal WSM packet*/
int build_gps_xmlentry(uint8_t logtype, char *buf, WSMIndication *wsm, additionalWSMP *nodeinfo, GPSData *gps,
                       int gpscontents) {
    static int seq = 0;
    static int inuse = 0;
    int ret = 0;
    int i = 0;
    struct timeval tv;
    char m[150];
    struct channelInfo ci;
//	float tempf = 0.0f;
    char lastsrc[20];
//	static long sec = 0;
//	static long usec = 0;
//	static long diff = 0;

    while (inuse);
    inuse = 1;

    if ((buf == NULL) || (wsm == NULL)) {
        inuse = 0;
        return -1;
    }
    memcpy(&ci, &wsm->chaninfo, sizeof(ci));
    seq++;
    sprintf(buf + i, "\n<logentry>\n");
    i += 12;

    sprintf(m, "<loginfo>\n");
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));
    sprintf(m, "<seq> %d </seq> ", seq);
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));
    gettimeofday(&tv, NULL);
#ifndef WIN32
    sprintf(m, "<logtime> <seconds> %llu </seconds> <microseconds> %d </microseconds> </logtime> ",
            (uint64_t) tv.tv_sec, (uint32_t) tv.tv_usec);
#else
    sprintf(m, "<logtime> <seconds> %llu </seconds> <microseconds> %d </microseconds> </logtime> ", tv.tv_sec, tv.tv_usec);
#endif
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    sprintf(m, "<src> %s </src>\n", (nodeinfo == NULL) ? _mac_sprintf(wsm->macaddr) : _mac_sprintf(nodeinfo->macaddr));
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    sprintf(m, "</loginfo>\n");
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    sprintf(m, "<packet>\n");
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));
    switch (logtype) {
        case 0:
            sprintf(m, "<type> %s </type>\n", (gps == NULL) ? "wsmp" : "gps_wsmp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<wsmp>\n");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<header>\n");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<psid> %d </psid> ", wsm->psid);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<ver> %u </ver> <sec> %u </sec> ", wsm->version, wsm->security);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<channel> %u </channel> <rateindex> %u </rateindex> <txpower> %u </txpower>\n", ci.channel,
                    ci.rate, ci.txpower);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "</header>\n");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "<data> ");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            if (gps) {
                memcpy(buf + i, "GPSDATA", 7);
                i += (7);
            } else {
                memcpy(buf + i, wsm->data.contents, wsm->data.length);
                i += (wsm->data.length);
            }
            sprintf(m, " </data>\n");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "</wsmp>\n");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 1:
            sprintf(m, "<type> %s </type>\n", "gps_udp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 2:
            sprintf(m, "<type> %s </type>\n", "gps_ip");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 3:
            sprintf(m, "<type> %s </type>\n", "gps_ip_udp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 4:
            sprintf(m, "<type> %s </type>\n", "gps_tx_local");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;
    }

    if (nodeinfo) {
        ret = nodeinfo->packetnum;
        if (isBigEndian())
            ret = swap32_(nodeinfo->packetnum);

        sprintf(m, "<nodeinfo>\n");
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
        sprintf(m, "<packetnum> %u </packetnum> <rssi> %u </rssi>\n", ret, wsm->rssi);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
        sprintf(lastsrc, "%s", (nodeinfo == NULL) ? _mac_sprintf(wsm->macaddr) : _mac_sprintf(nodeinfo->macaddr));
        if (logtype != 4) {
            if (find_src(lastsrc, ret, tv.tv_sec, tv.tv_usec) == NULL) {
                add_src(lastsrc, ret, tv.tv_sec, tv.tv_usec);
            }
        }
        sprintf(m, "</nodeinfo>\n");
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
    }

    if (gps) {
        sprintf(m, "<gps>\n");
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
        if (gpscontents & GPS_STG) {
            sprintf(m, "<gpsstring> ");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            if (logtype != 0) {
                for (ret = 0; ret < wsm->data.length; ret++)
                    buf[i + ret] = wsm->data.contents[ret];
                i += (wsm->data.length);
            } else {
                for (ret = 11; ret < wsm->data.length; ret++)
                    buf[i + ret - 11] = wsm->data.contents[ret];
                i += (wsm->data.length - 11);
            }
            sprintf(m, "</gpsstring> ");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_TIM) {
            sprintf(m, "<gpstime> %lf </gpstime> ", gps->time);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_LAT) {
            sprintf(m, "<latitude> %lf </latitude> <latdir> %c </latdir> ", gps->latitude,
                    (gps->latitude < 0) ? 'S' : 'N');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_LON) {
            sprintf(m, "<longitude> %lf </longitude> <londir> %c </londir> ", gps->longitude,
                    (gps->longitude < 0) ? 'W' : 'E');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_ALT) {
            sprintf(m, "<altitude> %lf </altitude> ", gps->altitude);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_SPD) {
            sprintf(m, "<speed> %lf </speed> ", gps->speed);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_DIR) {
            sprintf(m, "<direction> %lf </direction> ", gps->course);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_HDP) {
            sprintf(m, "<hdop> %lf </hdop> ", gps->hdop);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_VDP) {
            sprintf(m, "<vdop> %lf </vdop> ", gps->vdop);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_HEE) {
            sprintf(m, "<hee> %lf </hee> ", gps->hee);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_VEE) {
            sprintf(m, "<vee> %lf </vee> ", gps->vee);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_NSV) {
            sprintf(m, "<nsv> %u </nsv> ", gps->numsats);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_FIX) {
            sprintf(m, "<fix> %u </fix> ", gps->fix);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (gpscontents & GPS_TOW) {
            sprintf(m, "<gpstow> %lf </gpstow> ", gps->tow);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        sprintf(m, "\n</gps>\n");
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
    }
    sprintf(m, "</packet>\n");
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));
    sprintf(buf + i, "</logentry>");
    i += 11;
    inuse = 0;
    return i;
}

int build_gps_csventry(uint8_t logtype, char *buf, WSMIndication *wsm, additionalWSMP *nodeinfo, GPSData *gps,
                       int gpscontents) {
    static int seq = 0;
    static int inuse = 0;
    int ret = 0;
    int i = 0;
    struct timeval tv;
    char m[150];
    struct channelInfo ci;
//	float tempf = 0.0f;
    char lastsrc[20];
    uint64_t tsf = 0;
    int temp = 0;
//	static long sec =  0;
//	static long usec = 0;
//	static long diff = 0;

    while (inuse);
    inuse = 1;

    if ((buf == NULL) || (wsm == NULL)) {
        inuse = 0;
        return -1;
    }
    memcpy(&ci, &wsm->chaninfo, sizeof(ci));
    seq++;
    /*TO DO: For ACM and WSMDATA contents, surround double quotes with double quotes*/
    switch (logtype) {
        case 0:
            sprintf(m, " %s, ", (gps == NULL) ? "wsmp" : "gps_wsmp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, " %d, %c", wsm->psid, '"');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "%c, ", '"');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "%u, %u, ", wsm->version, wsm->security);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            sprintf(m, "%u, %u, %u, %c", ci.channel, ci.rate, ci.txpower, '"');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));

            if (gps) {
                sprintf(m, "GPSDATA");
                sprintf(buf + i, "%s ", m);
                i += (strlen(m));
            } else {
                memcpy(buf + i, wsm->data.contents, wsm->data.length);
                i += (wsm->data.length);
            }
            sprintf(m, "%c, ", '"');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            if (!gps)
                goto end_of_csv;

            break;

        case 1:
            sprintf(m, "%s, ", "gps_udp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 2:
            sprintf(m, "%s, ", "gps_ip");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 3:
            sprintf(m, "%s, ", "gps_ip_udp");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;

        case 4:
            sprintf(m, "%s, ", "gps_tx_local");
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            break;
    }
    sprintf(m, "%d, ", seq);
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));
    gettimeofday(&tv, NULL);

    /*NOTE: For CSV case, we use TSF in microseconds field, so that we can calculate IPD using difference in TSFs (using TIM_TSF on tx side)*/
    tsf = generatetsfRequest();
    temp = (int) tsf;
#ifndef WIN32
    //Uncomment the line below to put gettimeofday's usec as logtime
    //sprintf(m, "%llu, %d, ", (uint64_t)tv.tv_sec, (uint32_t)tv.tv_usec);
    sprintf(m, "%llu, %d, ", (uint64_t) tv.tv_sec, (uint32_t) temp);
#else
    sprintf(m, "%llu, %d, ", tv.tv_sec, tv.tv_usec);
#endif
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    sprintf(m, "%s, ", (nodeinfo == NULL) ? _mac_sprintf(wsm->macaddr) : _mac_sprintf(nodeinfo->macaddr));
    sprintf(buf + i, "%s ", m);
    i += (strlen(m));

    if (nodeinfo) {
        ret = nodeinfo->packetnum;
        if (isBigEndian())
            ret = swap32_(nodeinfo->packetnum);
        sprintf(m, "%u, %u, ", ret, nodeinfo->rssi);
        sprintf(buf + i, "%s, ", m);
        i += (strlen(m));
        sprintf(lastsrc, "%s", (nodeinfo == NULL) ? _mac_sprintf(wsm->macaddr) : _mac_sprintf(nodeinfo->macaddr));
        if (logtype != 4) {
            if (find_src(lastsrc, ret, tv.tv_sec, tv.tv_usec) == NULL) {
                add_src(lastsrc, ret, tv.tv_sec, tv.tv_usec);
            }
        }
    }

    if (gps) {
        if (gpscontents & GPS_STG) {
            sprintf(buf + i, "%c ", '"');
            i += (2);
            if (logtype != 0) {
                for (ret = 0; ret < wsm->data.length; ret++)
                    buf[i + ret] = wsm->data.contents[ret];
                i += (wsm->data.length);
            } else {
                for (ret = 11; ret < wsm->data.length; ret++)
                    buf[i + ret - 11] = wsm->data.contents[ret];
                i += (wsm->data.length - 11);
            }
            sprintf(m, "%c, ", '"');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
            goto end_of_csv;
        }
        if (1 || gpscontents & GPS_TIM) {
            sprintf(m, "%lf, ", gps->time);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_LAT) {
            sprintf(m, "%lf, %c, ", gps->latitude, (gps->latitude < 0) ? 'S' : 'N');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_LON) {
            sprintf(m, "%lf, %c, ", gps->longitude, (gps->longitude < 0) ? 'W' : 'E');
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_ALT) {
            sprintf(m, "%lf, ", gps->altitude);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_SPD) {
            sprintf(m, "%lf, ", gps->speed);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_DIR) {
            sprintf(m, "%lf, ", gps->course);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_HDP) {
            sprintf(m, "%lf, ", gps->hdop);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_VDP) {
            sprintf(m, "%lf, ", gps->vdop);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_HEE) {
            sprintf(m, "%lf, ", gps->hee);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_VEE) {
            sprintf(m, "%lf, ", gps->vee);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_NSV) {
            sprintf(m, "%u, ", gps->numsats);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_FIX) {
            sprintf(m, "%u, ", gps->fix);
            sprintf(buf + i, "%s", m);
            i += (strlen(m));
        }
        if (1 || gpscontents & GPS_TOW) {
            sprintf(m, "%lf, ", gps->tow);
            sprintf(buf + i, "%s ", m);
            i += (strlen(m));
        }
        end_of_csv:
        sprintf(m, "%cend%c", '"', '"');
        sprintf(buf + i, "%s ", m);
        i += strlen(m);
    }
    inuse = 0;
    return i;
}


