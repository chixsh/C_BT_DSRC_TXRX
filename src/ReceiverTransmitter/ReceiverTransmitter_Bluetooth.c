//
// Created by trl on 2/12/16.
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
#include "Bluetooth_Handler.h"
#include "DSRC_Handler.h"


static int pid;
char addr1[1024];

sem_t addr;
WSMIndication rxpkt;


int main(int arg, char *argv[]) {

    int thread_arg = 2;
    int rx_ret = -1, btooth_ret = -1;

    WSMMessage rxmsg;
    WSMIndication rxpkt;
    //int i, attempts = 10, drops = 0, result;
    int ret = 0;
    rxmsg.wsmIndication = &rxpkt;


    if (arg < 5) {
        printf("usage: ReceiverTransmitter_Bluetooth [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [PSID] [channel] [PROVIDER MAC <optional>]\n");
        return 0;
    }
    printf("Invoking WAVE driver \n");
    if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
        printf("Open Failed. Quitting\n");
        exit(-1);
    }
    printf("WAVE driver Invoked \n");
    Initialize_Bluetooth_Environment(arg, argv);
    Initialize_DSRC_RX_Environment(arg, argv);
    // Initialize_DSRC_TX_Environment(arg, argv);

    int LastOperation = RECEIVE_DSRC_MESSAGE;

    while (1) {
        //printf("Bluetooth_ConnectionStatus = %d \n", Bluetooth_ConnectionStatus);
        if (Bluetooth_ConnectionStatus != BluetoothIsConnected) {
            //usleep(10000);
            sched_yield();
            // printf("Bluetooth_ConnectionStatus = Connection Lost \n");

        } else {
            break;
        }

    }

    // sleep(60);

    // printf("Bluetooth_ConnectionStatus = %d \n", Bluetooth_ConnectionStatus);
    //if (Bluetooth_ConnectionStatus != BluetoothIsConnected) {
    //   printf("Bluetooth_ConnectionStatus = Connection Lost \n");

    // }
    printf("Bluetooth_ConnectionStatus = BluetoothIsConnected \n");


    while (1) {

        usleep(1000);
        if (LastOperation == SEND_DSRC_MESSAGE) { LastOperation = Receive_DSRC_Message(); }
        else { LastOperation = Send_DSRC_Message(); }

    }//while
}
