#ifndef UDP_H
#define UDP_H 1
#define UDP_H_CVS	"$Id: udp.h,v 1.4 2001/10/12 03:51:59 vikrum Exp $"
#define UDPHDRSIZE    sizeof(struct udphdr)
#define MAX_UDP_PACKET 1024

struct udphdr {
        u_short source;         /* source port */
        u_short dest;                   /* destination port */
        u_short len;                    /* udp length */
        u_short check;          /* udp checksum */
};
#endif
