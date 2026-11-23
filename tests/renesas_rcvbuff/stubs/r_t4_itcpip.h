/* Stand-in for the Renesas T4 header r_t4_itcpip.h, which these samples
 * include but which is not part of this tree. Types match the calls in the
 * sample clients. The byte-copy contract of tcp_rcv_dat / tcp_snd_dat is the
 * ITRON TCP/IP API (positive return = length copied) and M3S-T4-Tiny
 * _tcp_cpy_rwdat / _tcp_recv_polling, which memcpy at most the requested
 * length and return that count.
 */
#ifndef R_T4_ITCPIP_STUB_H
#define R_T4_ITCPIP_STUB_H

#include <stdint.h>

typedef int ID;
typedef int ER;
typedef int FN;
typedef void *VP;
typedef int TMO;
typedef int INT;

#define E_OK 0
#define TMO_FEVR (-1)

typedef struct {
    unsigned long ipaddr;
    unsigned short portno;
} T_IPV4EP;

ER tcp_con_cep(ID cepid, T_IPV4EP *myaddr, T_IPV4EP *dstaddr, TMO tmout);
ER tcp_rcv_dat(ID cepid, VP data, INT len, TMO tmout);
ER tcp_snd_dat(ID cepid, VP data, INT len, TMO tmout);
ER tcp_sht_cep(ID cepid);
ER tcp_cls_cep(ID cepid, TMO tmout);

#endif
