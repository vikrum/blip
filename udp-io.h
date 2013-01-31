#ifndef UDP_IO_H
#define UDP_IO_H 1
#define UDP_IO_H_CVS	"$Id: udp-io.h,v 1.5 2001/10/13 11:35:21 vikrum Exp $"
int udp_send_safe(int s, unsigned long saddr, unsigned long daddr,unsigned short sport,unsigned short dport,char *datagram, unsigned datasize);
int udp_send_eff(int s, unsigned long saddr, unsigned long daddr,unsigned short sport,unsigned short dport,char *datagram, unsigned datasize);
int udp_send_hack(int s, unsigned long saddr, unsigned long daddr, unsigned short s_port, unsigned short d_port, char *datagram, unsigned datasize);
#endif
