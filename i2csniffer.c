#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>

#define STATUS_IDLE 0x00
#define STATUS_STARTED 0x01
#define STATUS_ADDRTRANSMITTED 0x02

//Ugly bydlocode to communicate with Arduino I2C sniffer
//Author: cropinghigh, 2021

int main(int argc, char** argv) {
    int fd, ret;
    char* dev;
    struct termios tty;
    unsigned char buff[2], fbyte, sbyte, ptype, address, byteval, status, addrfilter;
    bool addrfilter_active;
    addrfilter_active = false;
    if(argc < 2) {
        printf("Wrong usage!Correct: %s [sniffer device, like /dev/ttyUSB1] [address of which only packets will be shown, decimal, if needed]\n", argv[0]);
        return 1;
    }
    if(argc >= 3) {
        addrfilter_active = true;
        addrfilter = atoi(argv[2]);
    }
    dev = argv[1];
    printf("Staring i2c sniffer on %s...\n", dev);
    fd = open(dev, O_RDONLY);
    if(fd < 0) {
        printf("open() for %s failed! Error: %s(%d)\n", dev, strerror(errno), errno);
        return 1;
    }
    if(tcgetattr(fd, &tty) != 0) {
        printf("tcgetattr() for %s failed! Error: %s(%d)\n", dev, strerror(errno), errno);
        close(fd);
        return 1;
    }
    tty.c_cflag &= ~CRTSCTS;   // Disable RTS/CTS control flow
    tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)
    tty.c_lflag &= ~ICANON;
    tty.c_lflag &= ~ECHO; // Disable echo
    tty.c_lflag &= ~ECHOE; // Disable erasure
    tty.c_lflag &= ~ECHONL; // Disable new-line echo
    tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP
    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // Disable any special handling of received bytess
    tty.c_cc[VTIME] = 0;    // Block, until 2 bytes available
    tty.c_cc[VMIN] = 2;
    cfsetispeed(&tty, B115200);
    if(tcsetattr(fd, TCSANOW, &tty) != 0) {
        printf("tcsetattr() for %s failed! Error: %s(%d)\n", dev, strerror(errno), errno);
        close(fd);
        return 1;
    }
    printf("Serial port parameters set! Now reading data...\n");
    status = STATUS_IDLE;
    while(1) {
        ret = read(fd, &buff, sizeof(buff));
        if(ret < 0) {
            printf("Error reading serial port(%d)!\n", ret);
            break;
        }
        if(ret != 2) {
            continue;               //We need exactly 2 bytes
        }
        fbyte = buff[0];
        sbyte = buff[1];
        if(((fbyte & 0b10000000) == 0) || (sbyte & 0b00000001) == 0) {
            printf("Corrupt packet received from i2c sniffer(0x%2x 0x%2x)!\n", fbyte, sbyte);
            continue;
        }
        ptype = (fbyte & 0b01110000) >> 4;
        switch(ptype) {
            case 0b000:
                printf("\nPACKET: CE %s Sniffer started\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"));
                break;
            case 0b001:
                printf("PACKET: CE %s Lines set up both HIGH\n\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"));
                break;
            case 0b010:
                if(status == STATUS_IDLE && !addrfilter_active) {
                    printf("\033[0;32mPACKET: CE %s Start bit received\033[0;37m\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"));
                } else if(status == STATUS_ADDRTRANSMITTED && (!addrfilter_active || ((address & 0xfe) == (addrfilter & 0xfe)))) {
                    printf("\033[0;32mPACKET: CE %s Repeated start bit received\033[0;37m\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"));
                }
                status = STATUS_STARTED;
                break;
            case 0b011:
                byteval = sbyte >> 1;
                byteval |= (fbyte & 0b00000001) << 7;
                if(status == STATUS_STARTED) {
                    address = byteval;
                    if((!addrfilter_active || ((address & 0xfe) == (addrfilter & 0xfe)))) {
                        printf("\033[0;33mPACKET: CE %s Received address: 0x%2x %s \033[0;37m\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"), byteval, (((fbyte & 0b00001000) == 0) ? "NACK" : "ACK"));
                    }
                    status = STATUS_ADDRTRANSMITTED;

                } else if(status == STATUS_ADDRTRANSMITTED) {
                    if((!addrfilter_active || ((address & 0xfe) == (addrfilter & 0xfe)))) {
                        printf("\033[0;33mPACKET: CE %s Received byte:    0x%2x %s \033[0;37m\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"), byteval, (((fbyte & 0b00001000) == 0) ? "NACK" : "ACK"));
                    }
                }
                break;
            case 0b100:
                if((!addrfilter_active || ((address & 0xfe) == (addrfilter & 0xfe)))) {
                    printf("\033[0;31mPACKET: CE %s Stop bit received\033[0;37m\n\n", (((fbyte & 0b00000100) == 0) ? "L" : "H"));
                }
                status = STATUS_IDLE;
                break;
            default:
                printf("Invalid packet type received from i2c sniffer(0x%2x)\n", ptype);
                break;
        }
    }
    close(fd);
    return 0;
}
