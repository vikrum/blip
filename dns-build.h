#ifndef DNS_BUILD_H
#define DNS_BUILD_H 1
#define DNS_BUILD_H_CVS		"$Id: dns-build.h,v 1.8 2001/10/13 11:35:21 vikrum Exp $"

int make_question_packet(char *data, char *name, int type, int class);
void set_dns_type(char *data, int type);
void set_dns_class(char *data, int class);
void nameformat (char *name, char *QS);
void make_dns_header(char *packet,
	unsigned short int      id,
	unsigned char           rd,
	unsigned char           tc,
	unsigned char           aa,
	unsigned char           opcode,
	unsigned char           qr,
	unsigned char           rcode,
	unsigned char           unused,
	unsigned char           pr,
	unsigned char           ra,
	unsigned short int      que_num,
	unsigned short int      rep_num,
	unsigned short int      num_rr,
	unsigned short int      num_rrsup);
void make_rand_dns_header(char *packet);
void set_dns_id(char *packet,  unsigned short int dns_id);
int make_zlip_packet(char *data, int type);
#endif
