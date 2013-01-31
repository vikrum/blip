#ifndef COMMON_H
#define COMMON_H 1
#define COMMON_H_CVS	"$Id: common.h,v 1.5 2001/10/13 11:35:21 vikrum Exp $"
#define getrandom(min, max) ((rand() % (unsigned long int)(((max-1)) - (min))) + (min))
#define MAX_32BIT       4294967296

void			*xcalloc (int factor, size_t size);
unsigned long		host2ip (char *host);
unsigned long		resolve(char *host);
unsigned short 		in_cksum(u_short *packet, int len);
char 			*ip_get_random (void);
int 			m_random (int lowmark, int highmark);
char 			*xstrdup (char *str);
#endif
