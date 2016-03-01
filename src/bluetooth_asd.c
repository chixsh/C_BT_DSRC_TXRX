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
#include <termio.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#define MAX_RSP 50


enum {
    FALSE = 0, TRUE
};
enum {
    ADDR_MAC = 0, UINT8
};
extern int Btooth_forward;

extern void sig_int(void);

void sig_int_bluetooth(void);

static int pid;
inquiry_info *info = NULL;
int loco_channel = -1, btooth_socket = -1;
int LSApp = -1;
int connection_established = FALSE;
char addr1[18];
sem_t addr;
char message[1024] = "";
sem_t len;

extern int get_canOption(char *, char *);

extern int write_to_can(char *);

int str2uuid(const char *uuid_str, uuid_t *uuid) {
    uint32_t uuid_int[4];
    char *endptr;

    if (strlen(uuid_str) == 36) {
        // Parse uuid128 standard format: 12345678-9012-3456-7890-123456789012
        char buf[9] = {0};

        if (uuid_str[8] != '-' && uuid_str[13] != '-' &&
            uuid_str[18] != '-' && uuid_str[23] != '-') {
            return 0;
        }
        // first 8-bytes
        strncpy(buf, uuid_str, 8);
        uuid_int[0] = htonl(strtoul(buf, &endptr, 16));
        if (endptr != buf + 8) return 0;

        // second 8-bytes
        strncpy(buf, uuid_str + 9, 4);
        strncpy(buf + 4, uuid_str + 14, 4);
        uuid_int[1] = htonl(strtoul(buf, &endptr, 16));
        if (endptr != buf + 8) return 0;

        // third 8-bytes
        strncpy(buf, uuid_str + 19, 4);
        strncpy(buf + 4, uuid_str + 24, 4);
        uuid_int[2] = htonl(strtoul(buf, &endptr, 16));
        if (endptr != buf + 8) return 0;

        // fourth 8-bytes
        strncpy(buf, uuid_str + 28, 8);
        uuid_int[3] = htonl(strtoul(buf, &endptr, 16));
        if (endptr != buf + 8) return 0;

        if (uuid != NULL) sdp_uuid128_create(uuid, uuid_int);
    } else if (strlen(uuid_str) == 8) {
        // 32-bit reserved UUID
        uint32_t i = strtoul(uuid_str, &endptr, 16);
        if (endptr != uuid_str + 8) return 0;
        if (uuid != NULL) sdp_uuid32_create(uuid, i);
    } else if (strlen(uuid_str) == 4) {
        // 16-bit reserved UUID
        int i = strtol(uuid_str, &endptr, 16);
        if (endptr != uuid_str + 4) return 0;
        if (uuid != NULL) sdp_uuid16_create(uuid, i);
    } else {
        return 0;
    }

    return 1;
}

void *main_bluetooth(void *arg) {
    int i, err, sock, dev_id = -1;
    int num_rsp = 0, max_rsp = 5, flags = 0, length = 4;  /* [1.28 *<length>]seconds [1.28*4 = 5.12] seconds */
    char addr[19] = {0};
    char cmd[100], cmd1[50];
    char name[248] = {0}, bt_mac[19] = "00:00:00:00:00:00";
    uuid_t uuid = {0};
    int application_id = (int) *(int *) arg;
    char uuid_str[50];
    FILE *fd = NULL;
    if (application_id == 2) {
        printf("\nOpen application: Android Locomate Messaging\n");
        strcpy(uuid_str, "66841278-c3d1-11df-ab31-001de000a901");
    }
    else if (application_id == 3) {
        printf("\nOpen application: Spat Andriod Application\n");
        strcpy(uuid_str, "66841278-c3d1-11df-ab31-001de000a903");
    }
    else if (application_id == 4) {
        printf("\nOpen application: Bluetooth CAN application\n");
        strcpy(uuid_str, "00001101-0000-1000-8000-00805F9B34FB");
        fd = popen("cat /var/can.conf | grep BTCAN_MAC= | cut -d '=' -f 2", "r");
        if (fd != NULL) {
            fscanf(fd, "%s", bt_mac);
            pclose(fd);
            printf("Mac from conf file: %s\n", bt_mac);
        }
    }
    else {
        printf("\nOpen application: Locomate Safety Application\n");
        strcpy(uuid_str, "66841278-c3d1-11df-ab31-001de000a902");
    }
    uint32_t range = 0x0000ffff;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    int status;
    int responses;
    int retries = 0;
    struct sockaddr_rc loc_addr = {0};
    signal(SIGINT, (void *) sig_int);

    /* find the bluetooth device is available or not */
    sprintf(cmd, "/usr/local/bin/hciconfig hci0 up");
    system(cmd);
    for (retries = 0; retries < 5; retries++) {
        dev_id = hci_get_route(NULL);
        if (dev_id < 0) {
            perror("No Bluetooth Adapter Available\n");
            sprintf(cmd, "/usr/local/bin/hciconfig hci0 down");
            system(cmd);
            sprintf(cmd1, "/usr/local/bin/hciconfig hci0 up");
            system(cmd1);
            printf("\nretry getting adapter : %d\n", retries);
        }
        else
            break;
    }
    if (retries == 5) {
        Btooth_forward = -1;
        return NULL;
    }

    for (retries = 0; retries < 5; retries++) { //check for the socket
        sock = hci_open_dev(dev_id);
        if (sock < 0) {
            perror("HCI device open failed");
            retries++;
            printf("\nretries sock : %d\n", retries);
        }
        else
            break;
    }
    if (retries == 5) {
        Btooth_forward = -2;
        return NULL;
    }

    for (retries = 0; retries < 5; retries++) { //check uuid is correct or not
        if (!str2uuid(uuid_str, &uuid)) {
            perror("Invalid UUID");
            retries++;
            printf("\nretries str2 uuid : %d\n", retries);
        }
        else
            break;
    }
    if (retries == 5) {
        Btooth_forward = -3;
        return NULL;
    }

    //printf("\nBluetooth Adapter Found \n");
    info = (inquiry_info *) malloc(MAX_RSP * sizeof(inquiry_info));

    while (1) { // loop to check and establish connection with other device

        while (connection_established == FALSE) {
            bzero(info, (MAX_RSP * sizeof(inquiry_info)));

            num_rsp = hci_inquiry(dev_id, length, max_rsp, NULL, &info,
                                  flags); // inquire for how many devices are available
            if (num_rsp < 0) {
                perror("Inquiry failed");
                sched_yield();
                sleep(1);
                continue;
            }
            printf("Inquiry devices found : %d\n", num_rsp);

            loco_channel = -1;
            for (i = 0; i < num_rsp; i++) {
                sdp_session_t *session;
                ba2str(&(info + i)->bdaddr, addr);
                printf("\nFound Mac: %s ", addr);
                if (application_id == 4 && strcmp("00:00:00:00:00:00", bt_mac)) // check for appid and mac_id
                if (strcasecmp(addr, bt_mac))
                    continue;
                memset(name, 0, sizeof(name));

                if (hci_read_remote_name(sock, &(info + i)->bdaddr, sizeof(name), name, 8000) < 0) //get devices by name
                    strcpy(name, "[unknown]");


                printf("Found : %s name : [[ %s ]]\n", addr, name);
                // connect to the SDP server running on the remote machine
                session = NULL;
                retries = 0;
                while (!session) {
                    session = sdp_connect(BDADDR_ANY, &(info + i)->bdaddr, 0);
                    if (session) break;
                    if (errno != 0) {
                        fprintf(stderr, "sdp_connect failed error no %d : %s \n", errno, strerror(errno));
                    }
                    if ((retries < 2) && ((errno == EALREADY))) {
                        retries++;
                        fprintf(stderr, "Retry sdp_connect %d\t", retries);
                        sched_yield();
                        usleep(300000);//300 ms
                        continue; //continue till 3 times
                    }
                    break;
                } /* while(!session) */
                if (session == NULL) {
                    if (i < (num_rsp - 1))
                        printf("Trying next device -> %d\n", i + 2);
                    continue;
                }

                search_list = NULL;
                attrid_list = NULL;
                response_list = NULL;

                search_list = sdp_list_append(NULL, &uuid); //append list of uuids
                attrid_list = sdp_list_append(NULL, &range); // append list of attributes
                err = 0;
                err = sdp_service_search_attr_req(session, search_list, SDP_ATTR_REQ_RANGE, attrid_list,
                                                  &response_list); //search for attributes from list
                sdp_list_t *r = response_list;
                responses = 0;


                // go through each of the service records
                for (; r; r = r->next) {
                    responses++;
                    sdp_record_t *rec = (sdp_record_t *) r->data;
                    sdp_list_t *proto_list;

                    // get a list of the protocol sequences
                    if (sdp_get_access_protos(rec, &proto_list) == 0) {
                        sdp_list_t *p = proto_list;

                        // go through each protocol sequence
                        for (; p; p = p->next) {
                            sdp_list_t *pds = (sdp_list_t *) p->data;

                            // go through each protocol list of the protocol sequence
                            for (; pds; pds = pds->next) {

                                // check the protocol attributes
                                sdp_data_t *d = (sdp_data_t *) pds->data;
                                int proto = 0;
                                for (; d; d = d->next) {
                                    switch (d->dtd) {
                                        case SDP_UUID16:
                                        case SDP_UUID32:
                                        case SDP_UUID128:
                                            proto = sdp_uuid_to_proto(&d->val.uuid);
                                            break;
                                        case SDP_UINT8:
                                            if (proto == RFCOMM_UUID) {
                                                printf("rfcomm channel: %d\n", d->val.int8);
                                                loco_channel = d->val.int8;
                                            }
                                            break;
                                    } /* switch(t->dtd) */
                                } /* for( ; d; d = d->next) */
                            } /* for( ; pds ; pds = pds->next) */
                            sdp_list_free((sdp_list_t *) p->data, 0);
                        } /* for( ; p; p = p->next) */
                        sdp_list_free(proto_list, 0);
                    } /* if(sdp_get_access_protos(rec, &proto_list)) */
                    sdp_record_free(rec);
                    if (loco_channel > 0) {
                        break;
                    }
                } /* for (; r; r = r->next) */


                sdp_list_free(response_list, 0);
                sdp_list_free(search_list, 0);
                sdp_list_free(attrid_list, 0);
                printf("No of services= %d on device %d \n", responses, i + 1);
                if (loco_channel > 0) {
                    // printf("Found Locomate Safety Application on device: name [%s], sending message now\n",name);
                    btooth_socket = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
                    loc_addr.rc_family = AF_BLUETOOTH;
                    loc_addr.rc_channel = loco_channel;
                    loc_addr.rc_bdaddr = (info + i)->bdaddr;
                    status = connect(btooth_socket, (struct sockaddr *) &loc_addr, sizeof(loc_addr));
                    if (status < 0) {
                        perror("\nuh oh: Btooth socket not created\n");
                        Btooth_forward = -5;
                    }
                    else {
                        sdp_close(session);
                        Btooth_forward = 1;
                        connection_established = TRUE;
                        break;
                    }
                }
                sdp_close(session);
            } /* for (i = 0; i < num_rsp; i++) */
            if (connection_established == FALSE) {
                printf("Scanning again\n");
                //sprintf(cmd, "/usr/local/bin/hciconfig hci0 down");
                //system(cmd);
                sprintf(cmd1, "/usr/local/bin/hciconfig hci0 up");
                system(cmd1);
                sched_yield();
                sleep(1);
            }
            else {
                printf("***Connection established***\n");
            }
        } /* while(connection_established == ...) */
        sched_yield();
        sleep(3); // wait for 3seconds, before next check
    }

}


int bt_write(char *data, int size) {
    int status = 0;
    pid = getpid();

    if (loco_channel > 0) {
        //sprintf(message,"%s",argv);
        //   status = write(btooth_socket, message, strlen(message));
        status = write(btooth_socket, data, size);
        //printf("\nwrite status %d",status);
        if (status < 0) {
            close(btooth_socket);
            btooth_socket = -1;
            loco_channel = -1;
            connection_established = FALSE;
            Btooth_forward = -4;
        }
        return status;
    }
    else {
        //printf("No Andriod application running \n");
        return -5555;
    }
}

int bt_read(char *data, int size) {

    int status = 0;
    if (loco_channel > 0) {
        status = read(btooth_socket, data, size);
        if (status < 0) {
            close(btooth_socket);
            btooth_socket = -1;
            loco_channel = -1;
            connection_established = FALSE;
            Btooth_forward = -4;
        }
        //printf("\nread status %d",status);
        return status;
    }

    return -1;
}

void sig_int_bluetooth(void) {
    //char cmd[50];

    if (info != NULL) {
        free(info);
    }
    if (btooth_socket >= 0) {
        close(btooth_socket);
    }
    //sprintf(cmd, "/usr/local/bin/hciconfig hci0 down");
    //system(cmd);
    //sprintf(cmd, "/usr/local/bin/hciconfig hci0 up");
    //system(cmd);

}
