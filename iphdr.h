#ifndef IPHDR_H
#define IPHDR_H

#pragma once

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;                /* header length */
    unsigned int ip_v:4;                /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;                /* version */
    unsigned int ip_hl:4;                /* header length */
#endif
    u_int8_t ip_tos;                        /* type of service */
    u_short ip_len;                        /* total length */
    u_short ip_id;                        /* identification */
    u_short ip_off;                        /* fragment offset field */
#define        IP_RF 0x8000                        /* reserved fragment flag */
#define        IP_DF 0x4000                        /* dont fragment flag */
#define        IP_MF 0x2000                        /* more fragments flag */
#define        IP_OFFMASK 0x1fff                /* mask for fragmenting bits */
    u_int8_t ip_ttl;                        /* time to live */
    u_int8_t ip_p;                        /* protocol */
    u_short ip_sum;                        /* checksum */
    Ip ip_src_;
    Ip ip_dst_;

    Ip ip_src() { return ntohl(ip_src_); }
    Ip ip_dst() { return ntohl(ip_dst_); }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)

#endif // IPHDR_H
