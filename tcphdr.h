#ifndef TCPHDR_H
#define TCPHDR_H

#pragma once

#include "iphdr.h"

#pragma pack(push,1)

struct TcpHdr final
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */

    /*u_int16_t sport() {return ntohs(th_sport);}
    u_int16_t dport() {return ntohs(th_dport);}
    uint32_t seq() {return ntohl(th_seq);}
    uint32_t ack() {return ntohl(th_ack);}
    uint16_t win() { return ntohs(th_win); }
    uint16_t sum() { return ntohs(th_sum); }
    uint16_t urp() { return ntohs(th_urp); }*/
};

#pragma pack(pop)

#endif // TCPHDR_H
