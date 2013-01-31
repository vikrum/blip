#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h> // IPPROTO_UDP
#include <arpa/inet.h>  // inet_ntoa()
#include <unistd.h>	// close()
#include <stdlib.h>	// system() EXIT_FAILURE
#include <string.h>	// strchr()
#include <time.h>
#include <signal.h>
#include "dns.h"
#include "common.h"
#include "dns-build.h"
#include "udp-io.h"
#include "mt19937int.h"
#include "build_id.h"

#define TOKEN_MAX	512
#define MAX_PACKET	1024
#define SERV_UDP_PORT   53

static char const cvsid[] = "$Id: blip.c,v 1.12 2001/10/13 11:35:21 vikrum Exp $";

static void     usage (char *program);
static void	version (char *program);
int		loop = 1;
int		debug = 1;

static void 
done(int signum) {
	if(debug) printf("+ Received signal %d; setting loop to zero\n", signum);
	loop = 0;
}

static void
version (char *program) {
	printf ("%s: %s\n%s", program, cvsid, build_id);
	exit (EXIT_SUCCESS);
}

static void
usage (char *program) {
        printf ("usage: %s [options] <dest1>[,dest2,dest3, .. destn]\n"
		"\n"
                "[options]\n"
		"   -s <n.n.n.n>		source ip address. use 0 for random\n"
                "   -j <n>		source port.  def: 4242; use 0 for random\n"
                "   -t <n>		query type.  def: 1; use 0 for random\n"
		"   -c <n>		class type.  def: 1; use 0 for random\n"
		"   -h <hostname>	hostname to lookup. default www.yahoo.com\n"
		"   -n <n>		number of packets to send. def: 1; use 0 for infinite\n"
		"   -l <n>		sleep between packets. def: 1; use 0 to not sleep\n"
		"   -d <n>		dns header id. def: 42; use 0 for random\n"
		"   -z <n>		zlip packet type.\n"
                "   -R			randomize dns header\n"
		"   -q			quiet output\n"
                "   -v			show version and exit successfully\n"
                "   -?			this help\n"
		"   <dest1>[,dest2, dest3 .. destn]  	destination ip address. use 0 for random\n"
                , program);
        exit (EXIT_FAILURE);
}

int
main(int argc, char **argv) {
  
	char			c;
	int			i, j = 0, k = 0,
				count = 1,
				sleep_s = 1,
				iterations = 1,
				zlipt = 0,
				source_port = 4242,
				sockd, type = 1, class = 1;
	unsigned short int	dns_id = 42;
	char			*hostname = NULL;
	char 			*token = NULL;
	char			*dns_packet;
	char 			*dns_payload;	// ptr to dns payload
	const int		true = 1;
	unsigned long int	s_ip = 0, d_ip = 0;	
	char			*source = 0, *dest = 0;
	char			**iplist;
	struct	in_addr		x_ip;
	struct			_randomize {
				unsigned int source_ip:1;
				unsigned int source_port:1;
				unsigned int dest_ip:1;
				unsigned int dns_header:1;
				unsigned int dns_id:1;
				unsigned int type:1;
				unsigned int class:1;
	} randomize;

	memset(&randomize,0, sizeof(struct _randomize));

        while ((c = getopt (argc, argv, "s:j:t:c:h:n:l:d:z:Rqv?")) != EOF) {
                switch (c) {
		case 's':
			source = xstrdup(optarg);
			break;
		case 'j':
			source_port = atoi(optarg);
			break;
		case 't':
			type = atoi(optarg);
			break;
		case 'c':
			class = atoi(optarg);
			break;
		case 'h':
			hostname = xstrdup(optarg);
			break;
		case 'n':
			iterations = atoi(optarg);
			break;
		case 'l':
			sleep_s = atoi(optarg);
			break;
		case 'd':
			dns_id = atoi(optarg);
			break;
		case 'z':
			zlipt = atoi(optarg);
			break;
		case 'R':
			randomize.dns_header = 1;
			break;
		case 'q':
			debug = 0;
			break;
		case 'v':
			version(argv[0]);
			break;
                case '?':
                        usage (argv[0]);
                        break;
                default:
                        usage (argv[0]);
			break;
                }
        }


	if( (argc != optind) ) {
		dest = xstrdup(argv[optind++]);
	}
	else {
		fprintf(stderr,"%s: destination required\n", argv[0]);
		usage(argv[0]);
	}

	if((sockd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}
 
	if(( setsockopt(sockd, IPPROTO_IP, IP_HDRINCL, (char *)&true, sizeof(true)) ) < 0) {
		perror("setsocketopt(IP_HDRINCL)");
		exit(EXIT_FAILURE);
	}

	signal(SIGTERM, done);
	signal(SIGQUIT, done);
	signal(SIGINT, done);

	sgenrand(time(NULL));

	if(!hostname)
		hostname = xstrdup("www.yahoo.com");
	
	if(source) {
		if (atoi(source) == 0) {
			randomize.source_ip = 1;
		}
		else {
			s_ip = resolve(source);
		};
	}
	else {
		source = xstrdup("0");
		s_ip = 0;
	}

	if(atoi(dest) == 0)
		randomize.dest_ip = 1;

	if(type == 0)
		randomize.type = 1;

	if(class == 0)
		randomize.class = 1;

	if(source_port == 0)
		randomize.source_port = 1;

	if(dns_id == 0)
		randomize.dns_id = 1;

	if(debug) printf("+ src: %s:%d dst: %s type: %d class: %d host: %s iter: %d sleep: %d\n",
		source, source_port, dest, type, class, hostname, iterations, sleep_s);

	token = (char *) xcalloc((TOKEN_MAX), (sizeof(char)));
	iplist = (char **) xcalloc(count, (sizeof(char *)));

	if ( (token = (char *)strtok(dest, ",")) )  {
		while(1) {
			iplist[count-1] = (char *)xstrdup(token);
			if(! (iplist = (char **) realloc((void *)iplist, (count+1)*(sizeof(char *)) )) ) {
				perror("realloc()");
				exit(EXIT_FAILURE);
			};
			if ( (! (token = (char *)strtok(NULL, ",")) )  || (token[0] == '\n')){
				break;
			}
			count++;
		}
	}

	free(token);
	free(source);
	free(dest);

	dns_packet = xcalloc(1,MAX_PACKET);
	dns_payload = (char *)(dns_packet+DNSHDRSIZE);
//	                       id,rd,tc,aa,opcode,qr,rcode,unused,pr,ra, que_num, rep_num, num_rr, num_rrsup
	make_dns_header(dns_packet,dns_id,1,0,0,0,0,0,0,0,0,1,0,0,0);

	if(zlipt) {
		i = make_zlip_packet(dns_payload, zlipt);
	}
	else {
		i = make_question_packet(dns_payload, hostname, type, class);
	}

	free(hostname);

	do {
		if(randomize.dns_header)
			make_rand_dns_header(dns_packet);

		if(randomize.source_ip)
			s_ip = genrand();

		if(randomize.dns_id)
			set_dns_id(dns_packet, (u_short)genrand());

		if(randomize.type)
			set_dns_type(dns_payload, (u_short)genrand());

		if(randomize.class)
			set_dns_class(dns_payload, (u_short)genrand());

		if(randomize.source_port)
			source_port = genrand();

		if(count == 1) {
			if(randomize.dest_ip) {
				d_ip = genrand();
			}
			else {
				if ((d_ip = resolve(iplist[j])) == 0)
					continue;
			};

			if(debug) { 
				x_ip.s_addr = s_ip;
				printf("+ sending packet from '%s' to ", inet_ntoa(x_ip) );
				x_ip.s_addr = d_ip;
				printf("'%s' type: %d class: %d\n", inet_ntoa(x_ip),
						ntohs(*((u_short *)(dns_payload+strlen(dns_payload)+1))), 
						ntohs(*((u_short *)(dns_payload+strlen(dns_payload)+3)))  );
			};
			udp_send_eff(sockd,s_ip,d_ip,source_port, 53, dns_packet, DNSHDRSIZE+i);
		}
		else {
			j = 0;
			do {
				if ((d_ip = resolve(iplist[j])) == 0)
					continue;
				udp_send_eff(sockd,s_ip,d_ip,source_port, 53, dns_packet, DNSHDRSIZE+i);
				j += 1;
			} while ( j < count-1 );
		}

		if( iterations != 0 ) 
			k++;
		if(sleep_s == 0)
			continue;
                if(iterations != 1)
			sleep(sleep_s);
	} while ( ((k == 0) || (k < iterations)) && (loop == 1) );

	close(sockd);
	free(dns_packet);

	for( j = 0; j < count; j++ ) {
		free(iplist[j]);
	}

	free(iplist);
	return EXIT_SUCCESS;
}
