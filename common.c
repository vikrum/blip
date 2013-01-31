#include <stdio.h>
#include <stdlib.h>	// calloc()
#include <netdb.h>	// gethostbyname()
#include <string.h>	// bzero/set
#include "ip.h"
#include "udp.h"

static char const cvsid[] = "$Id: common.c,v 1.6 2001/10/13 11:35:21 vikrum Exp $";

/*****************************************************************************/
/*
 * in_cksum --
 *  Checksum routine for Internet Protocol family headers (C Version)
 */
/*****************************************************************************/

unsigned short
in_cksum(u_short *packet, int len)
{
        register int nleft = len;
        register u_short *w = (u_short *)packet;
        register int sum = 0;
        u_short answer = 0;

        /*
        * Our algorithm is simple, using a 32 bit accumulator (sum), we add
        * sequential 16 bit words to it, and at the end, fold back all the
        * carry bits from the top 16 bits into the lower 16 bits.
        */
        while (nleft > 1)
        {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1)
        {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
        sum += (sum >> 16);         /* add carry */
        answer = ~sum;              /* truncate to 16 bits */
        return(answer);
}

unsigned long
resolve(char *host)
{
        struct sockaddr_in sinn;
        struct hostent *hent;

        if ((hent=gethostbyname(host))==NULL)
        {
                fprintf(stderr, "Unable to resolve host %s\n",host);
                return 0;
        }
        memset((char *)&sinn,0,sizeof(sinn));
        memcpy((char *)&sinn.sin_addr,hent->h_addr,hent->h_length);
        return sinn.sin_addr.s_addr;
}

void *
xcalloc (int factor, size_t size) {
	void    *moo;

	moo = calloc (factor, size);

	if (moo == NULL) {
		perror ("calloc()");
		exit (EXIT_FAILURE);
	}
	return (moo);

}

int
m_random (int lowmark, int highmark)
{
        long int        rnd;

        /* flip/swap them in case user messed up
         */
        if (lowmark > highmark) {
                lowmark ^= highmark;
                highmark ^= lowmark;
                lowmark ^= highmark;
        }
        rnd = lowmark;

        rnd += (random () % (highmark - lowmark));

        /* this is lame, i know :)
         */
        return (rnd);
}


char *
ip_get_random (void)
{
        char    *ip = xcalloc (1, 17);
        int     i[4];

        for (;;) {
                i[0] = m_random (1, 239);
                if (i[0] != 10 && i[0] != 127 && i[0] != 192)
                        break;
        }
        i[1] = m_random (1, 254);
        i[2] = m_random (1, 254);
        i[3] = m_random (1, 254);

        sprintf (ip, "%d.%d.%d.%d", i[0], i[1], i[2], i[3]);

        return (ip);
}

char *
xstrdup (char *str)
{
	/* From STRDUP(3):
	 * DESCRIPTION
	 * The  strdup()  function  returns a pointer to a new string
	 * which is a duplicate of the string s.  Memory for the  new
	 * string  is  obtained with malloc(3), and can be freed with
	 * free(3).
	 */
	
        char    *b;

        b = strdup (str);
        if (b == NULL) {
                perror("strdup()");
                exit (EXIT_FAILURE);
        }

        return (b);
}

/* from ping.c I think; haven't tried it out.. 
 * static void
 * rnd_fill(void)
 * {
 * 	static u_int32_t rnd;
 * 	int i;
 * 
 * 	for (i = PHDR_LEN; i < datalen; i++) {
 * 		rnd = (3141592621U * rnd + 663896637U);
 * 		opack_icmp.icmp_data[i] = rnd>>24;
 * 	}
 * }
 */
