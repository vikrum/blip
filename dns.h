#ifndef DNS_H
#define DNS_H 1
#define DNS_H_CVS		"$Id: dns.h,v 1.4 2001/10/12 03:51:59 vikrum Exp $"
#define DNSHDRSIZE 		12
#define DNS_MAX_PACKET 		512
#define TYPE_A			1
#define TYPE_NS              	2
#define TYPE_MD              	3
#define TYPE_MF              	4
#define TYPE_CNAME           	5
#define TYPE_SOA             	6
#define TYPE_MB              	7
#define TYPE_MG              	8
#define TYPE_MR              	9
#define TYPE_NULL            	10
#define TYPE_WKS             	11
#define TYPE_PTR             	12
#define TYPE_HINFO           	13
#define TYPE_MINFO           	14
#define TYPE_MX              	15
#define TYPE_TXT             	16
#define TYPE_AAAA            	28
#define TYPE_LOC             	29
#define TYPE_IXFR            	251
#define TYPE_AXFR            	252
#define TYPE_MAILB           	253
#define TYPE_MAILA           	254
#define TYPE_ANY		255

#define CLASS_IN		1
#define CLASS_CS		2
#define CLASS_CH		3
#define CLASS_HS		4
#define CLASS_ANY		255

/*
                        DNS Header Diagram

                                           1  1  1  1  1  1
             0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      ID                       |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    QDCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ANCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    NSCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ARCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	    
	    the difference between struct and diagram are due to endianess
*/

struct dnshdr {
	unsigned short int 	id;
	unsigned char  		rd:1;           /* recursion desired */
	unsigned char  		tc:1;           /* truncated message */
	unsigned char  		aa:1;           /* authoritive answer */
	unsigned char  		opcode:4;       /* purpose of message */
	unsigned char  		qr:1;           /* response flag */
	unsigned char  		rcode:4;        /* response code */
	unsigned char  		unused:2;       /* unused bits */
	unsigned char  		pr:1;           /* primary server required (non standard) */
	unsigned char  		ra:1;           /* recursion available */
	unsigned short int 	que_num;
	unsigned short int 	rep_num;
	unsigned short int 	num_rr;
	unsigned short int 	num_rrsup;
};
#endif
