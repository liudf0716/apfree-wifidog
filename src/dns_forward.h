#ifndef _DNS_FORWARD_H_
#define _DNS_FORWARD_H_

#define DNS_FORWARD_PORT 15353
#define LOCAL_DNS_PORT 53
#define MAX_DNS_NAME 256

// define a structure to hold the DNS header
struct dns_header {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char z :3;
    unsigned char ra :1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

void *dns_forward_thread(void *);

#endif