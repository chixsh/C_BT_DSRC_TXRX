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
        printf("usage: bluetoothrx [user req type<1-auto> <2-unconditional> <3-none>] [imm access] [extended access] [PSID] [channel] [PROVIDER MAC <optional>]\n");
        return 0;
    }
    printf("Invoking WAVE driver \n");
    if (invokeWAVEDevice(WAVEDEVICE_LOCAL, 0) < 0) {
        printf("Open Failed. Quitting\n");
        exit(-1);
    }
    printf("WAVE driver Invoked \n");
    Initialize_Bluetooth_Environment(arg, argv);
    Initialize_DSRC_Environment(arg, argv);

    while (1) { // starts rx packets and tx to bluetooth socket
        if (Bluetooth_ConnectionStatus == BluetoothConnectionLost) {
            usleep(100000);
        }
        rx_ret = rxWSMMessage(pid, &rxmsg); /* Function to receive the Data from TX application */
        sched_yield();

        if (rx_ret > 0) {
            printf("Received DSRC Message txpower= %d, rateindex=%d Packet No =#%llu#\n", rxpkt.chaninfo.txpower,
                   rxpkt.chaninfo.rate, Bluetooth_Count++);
            rxWSMIdentity(&rxmsg, 0); //Identify the type of received Wave Short Message.
            if (!rxmsg.decode_status) {
                Decode_BSM_Message_And_Forward_It_To_BlueTooth_Device(rxmsg);
                xml_print(rxmsg); /* call the parsing function to extract the contents of the received message */
            }
        }//if
        else {
            Bluetooth_Blank++;
        }
    }//while
    return 0;
}
