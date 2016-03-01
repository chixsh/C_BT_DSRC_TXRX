//
// Created by trl on 2/22/16.
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
#include <syslog.h>
#include "wave.h"
#include <asnwave.h>
#include <BasicSafetyMessage.h>
#include <netinet/tcp.h> //for TCP_NODELAY
#include "GPS_Handler.h"


// ~~~~~~~~~~~~~~~~~~  Constants  ~~~~~~~~~~~~~~~~~~
#define MAX_RSP 50
// ~~~~~~~~~~~~~~~~~~  enums  ~~~~~~~~~~~~~~~~~~
enum {
    FALSE = 0, TRUE
};
enum {
    ADDR_MAC = 0, UINT8
};
enum {
    BluetoothConnectionLost = 0, BluetoothIsConnected
};
struct arguments {
    u_int8_t macaddr[17];
    u_int8_t channel;
};
static uint64_t Bluetooth_Count = 0;
static uint64_t Bluetooth_Blank = 0;
static int pid;
static WMEApplicationRequest Bluetooth_Entry;
static int Bluetooth_ConnectionStatus;


// ~~~~~~~~~~~~~~~~~~  Methods Headers  ~~~~~~~~~~~~~~~~~~
void Bluetooth_Signal_Interrupt(void);

void Bluetooth_Signal_Terminate(void);

int String2UUID(const char *uuid_str, uuid_t *uuid);

int Bluetooth_Write(char *data, int size);

int Bluetooth_Read(char *data, int size);

int Bluetooth_ConfirmBeforeJoin(WMEApplicationIndication *appind);

void Bluetooth_Set_Arguments(void *data, void *argname, int datatype);

int Decode_BSM_Message_And_Forward_It_To_BlueTooth_Device(WSMMessage rxmsg);

int Initialize_Bluetooth_Environment(int arg, char *argv[]);

int Extract_MAC_Acaddress(u_int8_t *mac, char *str);

void *main_bluetooth(void *arg);


