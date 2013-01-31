#include <stdio.h>
#include <stdlib.h>		// free()
#include <sys/types.h>		// sendto()
#include <sys/socket.h>		// sendto()
#include <netinet/in.h>
#include "ip.h"
#include "udp.h"
#include "pseudo.h"
#include "common.h"

static char const cvsid[] = "$Id: udp-io.c,v 1.6 2001/10/13 11:35:21 vikrum Exp $";

int
udp_send_safe(int s, unsigned long saddr, unsigned long daddr,unsigned short sport,unsigned short dport,char *datagram, unsigned datasize)
{
	int			i;
        struct sockaddr_in	sin;
        struct iphdr		ip_head;
	struct pseudohdr	pseudo_head;
        struct udphdr		udp_head;
        char			*packet;

	struct help_checksum
	{
		struct pseudohdr phdr;
		struct udphdr uhdr;
	} udp_chk_construct;


        ip_head.version  	= 4;
        ip_head.ihl		= 5;
        ip_head.saddr.s_addr	= saddr;
        ip_head.daddr.s_addr	= daddr;
        ip_head.ttl		= 255;
        ip_head.id		= 42;
        ip_head.protocol	= IPPROTO_UDP;
        ip_head.tot_len		= htons(IPHDRSIZE + UDPHDRSIZE + datasize);
        ip_head.check		= 0;
        ip_head.check		= in_cksum((u_short *)&ip_head,IPHDRSIZE);

	udp_head.source		= htons(sport);
	udp_head.dest		= htons(dport);
	udp_head.len		= htons(UDPHDRSIZE+datasize);
	udp_head.check		= 0;

        pseudo_head.saddr	 = saddr;
	pseudo_head.daddr	 = daddr;
	pseudo_head.zero	 = 0;
	pseudo_head.protocol 	 = IPPROTO_UDP;
	pseudo_head.length	 = htons(UDPHDRSIZE+datasize);

	udp_chk_construct.phdr	= pseudo_head;
	udp_chk_construct.uhdr	= udp_head;

	packet = (char *)malloc(sizeof(struct help_checksum)+datasize);
	memcpy(packet,&udp_chk_construct,sizeof(struct help_checksum)+datasize);
	memcpy(packet+sizeof(struct help_checksum),datagram,datasize);
	udp_head.check=in_cksum((unsigned short *)packet,sizeof(struct help_checksum)+datasize);
	free(packet);

//	memset(&ip_head,0,sizeof(struct iphdr));
//	memset(&pseudo_head,0,sizeof(struct pseudohdr));
//	memset(&udp_head,0,sizeof(struct udphdr));

	packet = (char *)malloc(IPHDRSIZE+UDPHDRSIZE+datasize);
	memcpy(packet, (char *)&ip_head, IPHDRSIZE);
	memcpy(packet+IPHDRSIZE, (char *)&udp_head, UDPHDRSIZE);
	memcpy(packet+IPHDRSIZE+UDPHDRSIZE, datagram, datasize);

        sin.sin_family=AF_INET;
        sin.sin_addr.s_addr=daddr;
        sin.sin_port=udp_head.dest;
	
	i = sendto(s, packet, IPHDRSIZE+UDPHDRSIZE+datasize, MSG_DONTWAIT, (struct sockaddr*)&sin, sizeof(struct sockaddr));
	free(packet);

	if( i < 0 )
		return(-1);
	else
	        return(i);
}

int 
udp_send_eff(int s, unsigned long saddr, unsigned long daddr,unsigned short sport,unsigned short dport,char *datagram, unsigned datasize)
{
        struct sockaddr_in	sin;
        struct iphdr		*ip_head;
	struct pseudohdr	*pseudo_head;
        struct udphdr		*udp_head;
	unsigned char		*data;
        unsigned char		packet[MAX_UDP_PACKET];

	ip_head		= (struct iphdr     *)packet;
	pseudo_head	= (struct pseudohdr *)(packet+IPHDRSIZE-PSEUDOHDRSIZE);
	udp_head	= (struct udphdr    *)(packet+IPHDRSIZE);
	data 		= (unsigned char    *)(packet+IPHDRSIZE+UDPHDRSIZE);

	memset(packet, 0, MAX_UDP_PACKET);
	memcpy(data, datagram, datasize);

	udp_head->source	= htons(sport);
	udp_head->dest		= htons(dport);
	udp_head->len		= htons(UDPHDRSIZE+datasize);
	udp_head->check		= 0;

	if(saddr != 0) {
	        pseudo_head->saddr	 = saddr;
		pseudo_head->daddr	 = daddr;
		pseudo_head->zero	 = 0;
		pseudo_head->protocol 	 = IPPROTO_UDP;
		pseudo_head->length	 = htons(UDPHDRSIZE+datasize);
	
		udp_head->check		= in_cksum((u_short *)pseudo_head, PSEUDOHDRSIZE+UDPHDRSIZE+datasize);
	};

//	memset(packet,0, IPHDRSIZE);

        ip_head->saddr.s_addr	= saddr;
        ip_head->daddr.s_addr	= daddr;
        ip_head->version  	= 4;
        ip_head->ihl		= 5;
        ip_head->ttl		= 255; //        ip_head.id       = random()%5985;
        ip_head->id		= 42;
        ip_head->protocol	= IPPROTO_UDP;
        ip_head->tot_len	= htons(IPHDRSIZE + UDPHDRSIZE + datasize);
        ip_head->check		= 0;
        ip_head->check		= in_cksum((u_short *)ip_head,IPHDRSIZE);

        sin.sin_family=AF_INET;
        sin.sin_addr.s_addr=daddr;
        sin.sin_port=udp_head->dest;
	
	return(sendto(s, packet, IPHDRSIZE+UDPHDRSIZE+datasize, MSG_DONTWAIT, (struct sockaddr*)&sin, sizeof(struct sockaddr) ));
}

/* Keeping the these variants as reference */
int
udp_send_hack(int s, unsigned long saddr, unsigned long daddr, unsigned short s_port, unsigned short d_port, char *datagram, unsigned datasize) {

	struct sockaddr_in sin;
	struct iphdr     *ip;
	struct udphdr    *udp;
	struct pseudohdr *pseudo;
	unsigned char    *data;
	unsigned char packet[1024];

	ip     = (struct iphdr     *)packet;
	pseudo = (struct pseudohdr *)(packet+IPHDRSIZE-PSEUDOHDRSIZE);
	udp    = (struct udphdr    *)(packet+IPHDRSIZE);
	data   = (unsigned char    *)(packet+IPHDRSIZE+UDPHDRSIZE);
       
	memset(packet,0,1024);

        pseudo->saddr=saddr;
        pseudo->daddr=daddr;
        pseudo->zero=0;
        pseudo->protocol=17;
        pseudo->length=htons(UDPHDRSIZE+datasize);
                
        udp->source  = htons(s_port); 
        udp->dest    = htons(d_port);
        udp->len     = htons(UDPHDRSIZE+datasize);
        memcpy(data,datagram,datasize);
        udp->check    = 0;         
        udp->check   = in_cksum((u_short *)pseudo, PSEUDOHDRSIZE+UDPHDRSIZE+datasize);
        memcpy(data,datagram,datasize);
        
        memset(packet,0,IPHDRSIZE);
        
        ip->saddr.s_addr    = saddr;
        ip->daddr.s_addr    = daddr;
        ip->version  = 4;
        ip->ihl      = 5;
        ip->ttl      = 255;
        ip->id       = random()%5985;
        ip->protocol = 17;
        ip->tot_len  = htons(IPHDRSIZE + UDPHDRSIZE+ datasize);
        ip->check    = 0;
        ip->check    = in_cksum((u_short *)packet,IPHDRSIZE);

        sin.sin_family=AF_INET;
	sin.sin_addr.s_addr=daddr;
        sin.sin_port=udp->dest;

        return sendto(s, packet, IPHDRSIZE+UDPHDRSIZE+datasize, 0, (struct sockaddr*)&sin, sizeof(struct sockaddr));

}
