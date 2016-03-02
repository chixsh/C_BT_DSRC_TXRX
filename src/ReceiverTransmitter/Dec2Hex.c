//
// Created by trl on 3/2/16.
//

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


#include <termio.h>
#include <sys/types.h>
#include <sys/ioctl.h>


#define _FF000000 4278190080;
#define _00FF0000 16711680;
#define _0000FF00 65280;
#define _000000FF 255;

#define _0_Bytes 0;
#define _1_Bytes 8;
#define _2_Bytes 16;
#define _3_Bytes 24;


#define _F0 240;
#define _0F 15;

char Result[2];

char *Dec2Hex(short Number) {
    Result[0] = '0';
    Result[1] = '0';

    // printf("Dec2Hex. Number = %d :- Starting \n", Number);

    short N_0 = Number & _F0;
    N_0 = N_0 >> 4;
    short N_1 = Number & _0F;

    //  printf("\t short  N_0 = Number & F0. = %d ", N_0);
    //  printf("\t short  N_1 = Number & 0F. = %d \n", N_1);


    if (N_0 < 10) {
        Result[0] = N_0 + 48;
        //     printf("\t\t  N_0 < 10.  N_0 + 48. as Char = %c\n", Result[0]);
    }
    else {
        Result[0] = N_0 + 55;
        //    printf("\t\t  N_0 >= 10.  N_0 + 55. as Char = %c\n", Result[0]);
    }
    if (N_1 < 10) {
        Result[1] = N_1 + 48;
        //    printf("\t\t  N_1 < 10.  N_1 + 48. as Char = %c\n", Result[1]);
    }
    else {
        Result[1] = N_1 + 55;
        //   printf("\t\t  N_1 >= 10.  N_1 + 55. as Char = %c\n", Result[1]);
    }

    //  printf("Dec2Hex. Number = %d :- Ended With Result %s \n", Number, Result);
    return Result;
}


int longLatToFourBytes(double LongLat, short Bytes[4]) {

    printf("longLatToFourBytes. LongLat = %lf :- Starting \n", LongLat);

    ulong Number = (ulong)(LongLat * 10000000);

    printf("\tulong Number = LongLat * 10000000. = %ld ", Number);
    if (Number < 0) {
        printf("\tNumber is -ve. Adding .4294967296  = %ld \n", Number);
        Number = Number + 4294967296;
    } else {
        printf("\tNumber is +ve. No Change  = %ld \n", Number);
    }


/*
 *
 * #define _FF000000 4278190080;
 * #define _00FF0000 16711680;
 * #define _0000FF00 65280;
 * #define _000000FF 255;
 *
 *
 * #define _0_Bytes 0;
 * #define _2_Bytes 16;
 * #define _4_Bytes 32;
 * #define _6_Bytes 48;
 *
 *
 */

    ulong N_0 = Number & _FF000000;
    printf("\t\tulong N_0  = %ld & FF000000 = %ld \t", Number, N_0);
    N_0 = N_0 >> _3_Bytes; // Shift Right 6 Bytes
    printf("Shift N_0 Right 3 Bytes    = %ld\n", N_0);

    ulong N_1 = Number & _00FF0000;
    printf("\t\tulong N_1  = %ld & 00FF0000 = %ld  \t", Number, N_1);
    N_1 = N_1 >> _2_Bytes; // Shift Right 4 Bytes
    printf("Shift N_1 Right 2 Bytes    = %ld\n", N_1);

    ulong N_2 = Number & _0000FF00;
    printf("\t\tulong N_2  = %ld & 0000FF00 = %ld  \t", Number, N_2);
    N_2 = N_2 >> _1_Bytes; // Shift Right 2 Bytes
    printf("Shift N_2 Right 1 Bytes    = %ld\n", N_2);

    ulong N_3 = Number & _000000FF;
    printf("\t\tulong N_3  = %ld & 000000FF = %ld  \t", Number, N_3);
    N_3 = N_3 >> _0_Bytes; // Shift Right 0 Bytes
    printf("Shift N_3 Right 0 Bytes    = %ld\n", N_3);


    //           MS       LS
    // Octect =  N0 N1 N2 N3

    Bytes[0] = (short) N_0;
    Bytes[1] = (short) N_1;
    Bytes[2] = (short) N_2;
    Bytes[3] = (short) N_3;

    printf("longLatToFourBytes :- Ended \n");

}


int main(int Count, char *Arguments[]) {

    if (Count < 2) {
        printf("Format: CMD Number\n");
        exit(-1);
    }
    double Number = strtod(Arguments[1], NULL);

    short Bytes[4];
    Bytes[0] = 0;
    Bytes[1] = 0;
    Bytes[2] = 0;
    Bytes[3] = 0;

    longLatToFourBytes(Number, Bytes);

    int Index;

    for (Index = 0; Index < 4; Index++) {

        printf("Bytes[%d] = %d \t Hex = %s\n", Index, Bytes[Index], Dec2Hex(Bytes[Index]));

    }

    exit(0);
}
