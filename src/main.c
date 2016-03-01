#include <stdio.h>


int main() {

    double latitude = 32.8;
    double longitude = -96.5;
    double altitude = 2.2;
    double speed = 64;
    char GPSDATA[200];
    sprintf(GPSDATA, "latitude =\t%f\tlongitude =\t%f\taltitude =\t%f\tspeed =\t%f\t", latitude, longitude, altitude,
            speed);


    return 0;
}
