#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "genericAPI.h"
#include "wave.h"
#include <stdarg.h>
#include <sys/socket.h>// for socket()
#include <netinet/in.h>// for htons()
#include <netinet/tcp.h>// for TCP_NODELAY
#include <arpa/inet.h> //for inet_addr()
#include <sys/syslog.h> //for syslog stmnts

/***************************************************************************
 * 3. DECLARATIONS                                                         *
 ***************************************************************************/
static Time64 base_time = 0;
static int socket_id = -1;

/***************************************************************************
 * 4. IMPLEMENTATION                                                       *
 ***************************************************************************/

/*****************************************************
 * Convert host byte order to network byte order.    *
 *****************************************************/

unsigned int gen_htonl(unsigned int var) {
    return htonl(var);
}

UINT16 gen_htons(UINT16 var) {
    return htons(var);
}

/*****************************************************
 * Convert network byte order to host byte order.    *
 *****************************************************/
unsigned int gen_ntohl(unsigned int var) {
    return ntohl(var);
}

UINT16 gen_ntohs(UINT16 var) {
    return ntohs(var);
}

/*****************************************************
 * Memory copy.					     *
 *****************************************************/
void *gen_memcpy(void *to, const void *from, unsigned int n) {
    return memcpy(to, from, n);
}

/*******************************************************
 * Get the 00:00:00 1/1/2004 base time in microseconds.*
 *******************************************************/
Time64
get_base_time(void) {
    UINT64 b_time = 0;
    struct tm b_time_info;
    b_time_info.tm_year = 2004 - 1900;
    b_time_info.tm_mon = 1 - 1;
    b_time_info.tm_mday = 1;
    b_time_info.tm_hour = 0;
    b_time_info.tm_min = 0;
    b_time_info.tm_sec = 0;
    b_time_info.tm_isdst = -1;
    b_time = timegm(&b_time_info);
    b_time = b_time * 1000 * 1000;
    return b_time;
}

/*****************************************************
 * Convert host byte order to network byte order.    *
 *****************************************************/
Time64
htonll(
        const Time64 htime) {
    UINT32 x = 1;
    if (*(char *) &x == 1) {
        return ((((Time64) gen_htonl(htime)) << 32) | gen_htonl(htime >> 32));
    }
    return htime;
}

/*****************************************************************
 * Get the current time in microseconds since 00:00:00 1/1/2004. *
 *****************************************************************/
Time64 gen_getcurrentTime(void) {
    struct timeval tv;
    Time64 time_us = 0;

    if (0 != gettimeofday(&tv, NULL)) {
        ERROR("gettimeofday() failed. errno=[%d]", errno);
        exit(1);
    }
    time_us = tv.tv_sec;
    time_us = time_us * 1000 * 1000;
    time_us += tv.tv_usec;
    if (base_time == 0) {
        base_time = get_base_time();
    }
    return time_us - base_time - NUMBER_OF_LEAP_MICROSECONDS_TODAY;
}

/*********************************************************
 * Read an external file which is including the private key, *
 * certificate or signedCRL data.                        *
 *********************************************************/
int gen_readfile(const char *file, UINT8 *buff, int buffsize) {
    FILE *fd = 0;
    int size = 0;
    char str[4];
    char *ret = 0;
    unsigned int value = 0;
    fd = fopen(file, "rb");
    if (NULL == fd) {
        ERROR("fopen() failed. file=[%s]", file);
        exit(1);
    }

    while (size < buffsize) {
        ret = fgets(str, 4, fd);
        if (feof(fd)) {
            break;
        }
        if (NULL == ret) {
            ERROR("File format error. index=[%d]", size);
            exit(1);
        }

        value = 0;
        sscanf(str, "%x ", &value);
        buff[size] = (UINT8) value;
        size++;
    }
    fclose(fd);
    return size;
}

/************************************************
 * Output log message into stdout.              *
 ************************************************/
void
log_output(
        const int level,
        const char *file,
        const int line,
        const char *fmt,
        ...) {
    va_list argp;
    char buff[256];

    // get arguments
    va_start(argp, fmt);
    vsprintf(buff, fmt, argp);

    switch (level) {
        case LOG_LEVEL_ERROR:
            fprintf(stdout, "%s %d: ERROR %s\n", file, line, buff);
            break;
        case LOG_LEVEL_DEBUG:
            fprintf(stdout, "%s %d: DEBUG %s\n", file, line, buff);
            break;
        case LOG_LEVEL_INFO:
            //fprintf(stdout, "%s\n", buff);
            break;
        default:
            fprintf(stdout, "Unknown level [%d]\n", level);
    }
}

static int
tcp_init(
        const char *addr,
        const int port) {
    struct sockaddr_in sockAddr;
    int i = 0;
    int on = 1;

    // create socket
    socket_id = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_id < 0) {
        ERROR("socket() failed. errno=[%d]", errno);
        return -1;
    }
    if (0 != setsockopt(socket_id, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        ERROR("setsockopt() failed. errno=[%d]", errno);
        return -1;
    }
    if (0 != setsockopt(socket_id, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on))) {
        ERROR("setsockopt() NODELAY failed. errno=[%d]", errno);
        return -1;
    }
    // connect to Security Module
    INFO("Connecting ...");
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(addr);
    sockAddr.sin_port = htons(port);
    for (i = 0; i < 10; i++) {
        if (0 == connect(socket_id, (struct sockaddr *) &sockAddr, sizeof(sockAddr))) {
            break;
        }
        INFO("connect NG. retry");
        sleep(1);
    }
    if (i == 10) {
        ERROR("connect() failed. errno=[%d]", errno);
        return -1;
    }
    INFO("Connected.");
    return socket_id;
}

static int
tcp_send(
        const void *buff,
        const int buffSize,
        int soid) {
    int size = 0;

    size = send(soid, buff, buffSize, 0);
    if (size < 0) {
        ERROR("send() failed. errno=[%d]", errno);
        syslog(LOG_INFO, "AsmSend Failed. Restarting apps\n");
        system("/usr/local/bin/asmrestart.sh &");
        return -1;
    }
    if (size != buffSize) {
        ERROR("Message can not be sent correctly. buff size=[%d] send size=[%d]", buffSize, size);
        return -1;
    }
    return 0;
}

static int
tcp_recv(
        void *buff,
        const int buffSize, int soid) {
    int size = 0;

    size = recv(soid, buff, buffSize, 0);
    if (size < 0) {
        ERROR("recv() failed. errno=[%d]", errno);
        syslog(LOG_INFO, "AsmRecv Failed. Restarting apps\n");
        system("/usr/local/bin/asmrestart.sh &");
        return -1;
    }
    else if (size == 0) {
        ERROR("Message size is 0.");
        syslog(LOG_INFO, "AsmRecv Failed. Restarting apps\n");
        system("/usr/local/bin/asmrestart.sh &");
        return -1;
    }
    return size;
}

static void
tcp_close(int socketid) {
    close(socketid);
}

/*****************************************************
 * Initialize TCP network.                           *
 * This function establishes a connection with the SM. *
 *****************************************************/
int AsmConnect(int check, char *ip) {
    int ret;
    char remoteIP[IP_LEN];

    memset(remoteIP, 0, sizeof(remoteIP));
    memcpy(remoteIP, ip, sizeof(remoteIP));
    printf("Connecting to remote IP %s\n", remoteIP);
    if (check == 1)
        ret = tcp_init(remoteIP, 50000);
    else
        ret = tcp_init(remoteIP, 50000);

    if (ret < 0) {
        INFO("Could not connect to Asm. Please make sure that the IP address specified in the main.c file is correct!");
        return -1;
    }
    return ret;
}

/************************************************
 * Close the connection with the SM.            *
 ************************************************/
void AsmDisconnect(int txsocket_id, int rxsocket_id) {
    if (txsocket_id > 0)
        tcp_close(txsocket_id);
    if (rxsocket_id > 0)
        tcp_close(rxsocket_id);
}

/************************************************
 * Send a message to the SM.                    *
 ************************************************/
int AsmSend(char *buff, const int buffSize, int soid) {
    return tcp_send(buff, buffSize, soid);
}

int lcmSend(char *buff, const int buffSize) {
    struct sockaddr_in si_other;
    int s, slen = sizeof(si_other);
    int sendlen = 0;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        return -1;

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(16093);
    if (inet_aton("127.0.0.1", &si_other.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        close(s);
        return -1;
    }

    sendlen = sendto(s, buff, buffSize, 0, &si_other, slen);
    if (sendlen <= 0) {
        close(s);
        return -1;
    }

    close(s);
    return sendlen;
}

/************************************************
 * Receive a message from the SM.               *
 ************************************************/
int AsmRecv(char *buff, const int buffSize, int soid) {
    return tcp_recv(buff, buffSize, soid);
}

int getValbyLen(uint8_t *addr, int *retIdx) {
    int recv_size = 0;

    if ((addr[0] & 0x80) == 0x00) {
        recv_size = addr[0];
        recv_size = recv_size & 0x7fff;
        *retIdx = 1;
    }
    else if ((addr[0] & 0xc0) == 0x80) {
        recv_size = (addr[0] << 8) | (addr[1]);
        recv_size = recv_size & 0x3fff;
        *retIdx = 2;
    }
    else if ((addr[0] & 0xe0) == 0xc0) {
        recv_size = (addr[0] << 16) | (addr[1] << 8) | (addr[2]);
        recv_size = recv_size & 0x1fff;
        *retIdx = 3;
    }
    else if ((addr[0] & 0xf0) == 0xe0) {
        recv_size = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | (addr[3]);
        recv_size = recv_size & 0x0fff;
        *retIdx = 4;
    }
    return recv_size;
}

uint32_t getPsidbyLen(uint8_t *addr, int *retIdx) {
    uint32_t recv_size = 0;

    if ((addr[0] & 0x80) == 0x00) {
        recv_size = addr[0];
        *retIdx = 1;
    }
    else if ((addr[0] & 0xc0) == 0x80) {
        recv_size = (addr[0] << 8) | (addr[1]);
        *retIdx = 2;
    }
    else if ((addr[0] & 0xe0) == 0xc0) {
        recv_size = (addr[0] << 16) | (addr[1] << 8) | (addr[2]);
        *retIdx = 3;
    }
    else if ((addr[0] & 0xf0) == 0xe0) {
        recv_size = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | (addr[3]);
        *retIdx = 4;
    }
    return recv_size;
}

uint32_t putPsidbyLen(uint8_t *addr, uint32_t psid, int *retIdx) {
    uint32_t retPsid = 0;
    retPsid = *(uint32_t *) addr;
//                WME_PRINTF("---WSMP:Tx WSM Packet PSID:%x--addr:%x\n",psid,retPsid);
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

int32_t decode_length(uint8_t *addr, int32_t *retIdx) {
    int32_t recv_size = 0;

    if ((addr[0] & 0x80) == 0x00) {
        recv_size = addr[0];
        *retIdx = 1;
    }
    else if ((addr[0] & 0xc0) == 0x80) {
        recv_size = (addr[0] << 8) | (addr[1]);
        recv_size = recv_size & 0x3fff;
        *retIdx = 2;
    }
    else if ((addr[0] & 0xe0) == 0xc0) {
        recv_size = (addr[0] << 16) | (addr[1] << 8) | (addr[2]);
        recv_size = recv_size & 0x1fffff;
        *retIdx = 3;
    }
    else if ((addr[0] & 0xf0) == 0xe0) {
        recv_size = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | (addr[3]);
        recv_size = recv_size & 0x0fffffff;
        *retIdx = 4;
    }
    return recv_size;
}

