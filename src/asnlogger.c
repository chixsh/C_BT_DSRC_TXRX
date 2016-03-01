#include <pthread.h>
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
#include <sys/syslog.h>
#include <tgmath.h>
#include "wave.h"
#include "wavelogger.h" //pvk
#include <asnwave.h>
#include <asn_application.h>
#include <asn_internal.h>
#include <BasicSafetyMessage.h>
#include <RoadSideAlert.h>
#include <ProbeVehicleData.h>
#include <crc.h>
#include "tool_def.h"
#include "AsmDef.h"
#include "can_gds.h"
#include <IntersectionCollision.h>
#include <MapData.h>
#include <SPAT.h>
#include <semaphore.h>
#include "genericAPI.h"
#include <math.h>


int AsnLog(int from_txrx, uint8_t pktnum, int msgType, int logFormat, char *buf, void *asnData, void *wsm, double time,
           uint16_t sec_16) {
    static int seq = 0;
    static int inuse = 0;
    int ret = 0, i = 0, complete_capture = 0, k = 0;
    struct timeval tv;
    char m[150];
    char asnType[20];
    WSMIndication *wsmind = NULL;

    while (inuse);
    inuse = 1;
    if ( /*(buf == NULL) ||*/ (wsm == NULL)) {
        inuse = 0;
        return -1;
    }
    gettimeofday(&tv, NULL);

//.....logfmt pcap ...

    if (logFormat == PCAP || logFormat == PCAPHDR)           //pcap(default)
    {
        if (logFormat == PCAP) {
            complete_capture = 1;
        }
        if (time == 0) {
            time = (double) tv.tv_sec;
        }

        i = local_logging_client(from_txrx, wsm, time, ((sec_16 % 1000) * 1000), complete_capture, buf);
        inuse = 0;
    }
    else {
        wsmind = (WSMIndication *) wsm;
    }

    if (logFormat == CSV) {
        seq++;
        sprintf(buf + i, "\n [BEGIN] \n");
        i += 8;

        sprintf(m, "<seq=%d> ", seq);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

#ifndef WIN32
        sprintf(m, "<logtime seconds=%llu microseconds=%d> ", (uint64_t) tv.tv_sec, (uint32_t) tv.tv_usec);
#else
        sprintf(m, "<logtime seconds=%llu microseconds=%d> ", tv.tv_sec, tv.tv_usec);
#endif
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<src=%s> ", _mac_sprintf(wsmind->macaddr));
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        if (msgType == WSMMSG_BSM)
            strcpy(asnType, "BSM");
        else if (msgType == WSMMSG_PVD)
            strcpy(asnType, "PVD");
        else if (msgType == WSMMSG_RSA)
            strcpy(asnType, "RSA");
        else if (msgType == WSMMSG_ICA)
            strcpy(asnType, "ICA");

        sprintf(m, "<psid=%d> ", wsmind->psid);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<ver=%u> <sec=%u> ", wsmind->version, wsmind->security);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<channel=%u> <rateindex=%u> <txpower=%u> ", wsmind->chaninfo.channel, wsmind->chaninfo.rate,
                wsmind->chaninfo.txpower);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        if (msgType == WSMMSG_BSM) {
            BasicSafetyMessage_t *bsm_data = (BasicSafetyMessage_t *) asnData;

            sprintf(buf + i, "[BLOB] \n");
            i += 6;
            for (k = 0; k < 38; k++) {
                sprintf(m, "%x ", bsm_data->blob1.buf[k]);
                sprintf(buf + i, "%s ", m);
                i += (strlen(m));
            }
            if (bsm_data->status != NULL) {
                struct FullPositionVector *fpv = (struct FullPositionVector *) (bsm_data->status->fullPos);
                if (fpv != NULL) {
                    sprintf(buf + i, "[DATA]");
                    i += 6;

                    if (fpv->utcTime != NULL) {
                        sprintf(m, "<UTC TIME: Year=%ld Month=%ld Day=%ld Hour=%ld Min=%ld sec=%ld> ",
                                *fpv->utcTime->year, *fpv->utcTime->month, *fpv->utcTime->day, *fpv->utcTime->hour,
                                *fpv->utcTime->minute, *fpv->utcTime->second);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->Long != NULL) {
                        sprintf(m, "<longitude=%ld %c> ", fpv->Long, (fpv->Long < 0) ? 'W' : 'E');
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }
                    if (fpv->lat != NULL) {
                        sprintf(m, "<latitude=%ld %c> ", fpv->lat, (fpv->lat < 0) ? 'S' : 'N');
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->elevation != NULL) {
                        sprintf(m, "<elevation=%2u> ", (BIGENDIAN) ? (*(uint16_t *) fpv->elevation->buf) : swap16(
                                *(uint16_t *) fpv->elevation->buf));
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->speed != NULL) {
                        sprintf(m, "<speed=%hd> ",
                                (BIGENDIAN) ? (*(uint16_t *) fpv->speed->buf) : swap16(*(uint16_t *) fpv->speed->buf));
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }
                    if (fpv->heading != NULL) {
                        sprintf(m, "<heading=%ld> ", *fpv->heading);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->posAccuracy != NULL) {
                        sprintf(m, "<positionalAccuracy=%d> ", *fpv->posAccuracy->buf);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->posConfidence != NULL) {
                        sprintf(m, "<positionConfidence=%u> ", *fpv->posConfidence->buf);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->speedConfidence != NULL) {
                        sprintf(m, "<speedConfidence=%u> ", *fpv->speedConfidence->buf);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }
                }//fpv
                else {
                    sprintf(buf + i, "[BSM part II not present]");
                    i += 25;
                }

            }//bsm_status
        }//msgType

        sprintf(buf + i, "[END]\n");
        i += 5;
        inuse = 0;
    }//CSV

    if (logFormat == XML) {
        seq++;
        sprintf(buf + i, "[BEGIN] \n");
        i += 8;

        sprintf(m, "<seq=%d> \n", seq);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

#ifndef WIN32
        sprintf(m, "<logtime seconds> %llu </logtime seconds> \n", (uint64_t) tv.tv_sec);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
        sprintf(m, "<microseconds> %d </microseconds> \n", (uint32_t) tv.tv_usec);
#else
        sprintf(m, "<logtime seconds> %llu </logtime seconds> \n", tv.tv_sec);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));
        sprintf(m, "<microseconds> %d </microseconds> \n", tv.tv_usec);
#endif
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<src> %s </src> \n", _mac_sprintf(wsmind->macaddr));
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        if (msgType == WSMMSG_BSM)
            strcpy(asnType, "BSM");
        else if (msgType == WSMMSG_PVD)
            strcpy(asnType, "PVD");
        else if (msgType == WSMMSG_RSA)
            strcpy(asnType, "RSA");
        else if (msgType == WSMMSG_ICA)
            strcpy(asnType, "ICA");

        sprintf(m, "<type> %s </type> \n", asnType);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<psid> %hd </psid> \n", wsmind->psid);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<ver> %u </ver> \n", wsmind->version);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        sprintf(m, "<sec> %u </sec> \n", wsmind->security);
        sprintf(buf + i, "%s ", m);
        i += (strlen(m));

        if (msgType == WSMMSG_BSM) {
            BasicSafetyMessage_t *bsm_data = (BasicSafetyMessage_t *) asnData;

            sprintf(buf + i, "[BLOB] ");
            i += 6;
            for (k = 0; k < 38; k++) {
                sprintf(m, "%x ", bsm_data->blob1.buf[k]);
                sprintf(buf + i, "%s ", m);
                i += (strlen(m));
            }
            if (bsm_data->status != NULL) {
                struct FullPositionVector *fpv = (struct FullPositionVector *) (bsm_data->status->fullPos);
                if (fpv != NULL) {
                    sprintf(buf + i, "[DATA]");
                    i += 6;

                    if (fpv->utcTime != NULL) {
                        sprintf(m, " \n<Year>%ld </Year>\n", *fpv->utcTime->year);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }


                    if (fpv->utcTime != NULL) {
                        sprintf(m, " <Month>%ld </Month>\n", *fpv->utcTime->month);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->utcTime != NULL) {
                        sprintf(m, " <Day>%ld </Day>\n", *fpv->utcTime->day);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->utcTime != NULL) {
                        sprintf(m, " <Hour>%ld </Hour>\n", *fpv->utcTime->hour);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->utcTime != NULL) {
                        sprintf(m, " <Min>%ld </Min>\n", *fpv->utcTime->minute);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->utcTime != NULL) {
                        sprintf(m, "<sec>%ld </sec>\n", *fpv->utcTime->second);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->Long != NULL) {
                        sprintf(m, "<longitude> %ld </longitude> <londir> %c </londir> \n", fpv->Long,
                                (fpv->Long < 0) ? 'W' : 'E');
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->lat != NULL) {
                        sprintf(m, "<latitude> %ld </latitude> <latdir> %c </latdir> \n", fpv->lat,
                                (fpv->lat < 0) ? 'S' : 'N');
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->elevation != NULL) {
                        sprintf(m, "<elevation>%2u <elevation> ",
                                (BIGENDIAN) ? (*(uint16_t *) fpv->elevation->buf) : swap16(
                                        *(uint16_t *) fpv->elevation->buf));
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->speed != NULL) {
                        sprintf(m, "<speed>%hd </speed>\n",
                                (BIGENDIAN) ? (*(uint16_t *) fpv->speed->buf) : swap16(*(uint16_t *) fpv->speed->buf));
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->heading != NULL) {
                        sprintf(m, "<heading>%ld </heading>\n", *fpv->heading);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->posAccuracy != NULL) {
                        sprintf(m, "<positionalAccuracy>%d </positionalAccuracy> \n", *fpv->posAccuracy->buf);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->posConfidence != NULL) {
                        sprintf(m, "<positionConfidence>%u </positionConfidence> \n", *fpv->posConfidence->buf);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }

                    if (fpv->speedConfidence != NULL) {
                        sprintf(m, "<speedConfidence>%u <speedConfidence> \n", *fpv->speedConfidence->buf);
                        sprintf(buf + i, "%s ", m);
                        i += (strlen(m));
                    }
                }
                else {
                    sprintf(buf + i, "[BSM part II not present]");
                    i += 25;
                }//fpv-else
            }//bsm_data->status

        }//msgType

        sprintf(buf + i, "[END] \n");
        i += 5;
        inuse = 0;
    }//XML		 

    ret = write_logentry(buf, i);
    if (ret == FILE_SIZE_EXCEDDED)
        printf("[LOGGING: FILE SIZE EXCEDDED]\n");
    return i;
}


	
 
