//
// Created by TRL on 2/12/2016.
//

#include "DSRC_TX_Handler.h"

int Initialize_DSRC_TX_Environment(int arg, char *argv[]) {


}

void *DSRC_TX_Main_Thread(void *arg) {

    pthread_t CurrentThread_ID = pthread_self();

    AllocatedThreads[2] = CurrentThread_ID;

}
