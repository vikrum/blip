This code is unmaintained; it was pulled off of archive.org for nostalgic purposes only. :)

blip
====

A flexible DNS packet creation utility, load generator, and query only drone.blip

Status: Release 1.0 ($Id: blip.c,v 1.12 2001/10/13 11:35:21 vikrum Exp $)
[ DOWNLOAD | MD5: 401f1e7f24c3bc42a6dcf029f5475774 blip-1.0.tar.gz | SOURCE ]
Synopsis

blip is designed to query numerous name servers for a specific host, type and class without any concern for responses. It can be configured to run for a fixed number of iterations or without end. Each run cycle can be configured for a set delay time or no delay at all. The delay is meant to coincide with the resource record's TTL -- the intent being to keep the RR cached on the name server.

Extra Features

With this combination of options blip also has a set of extra features which allow it to also function as a load generator for DNS implementation testing. Packet creation can be configured to be randomized or repetitive; various components of the IP and UDP layer can also be set. 

DNS packets created by hand are also included as 'zlip type packets' -- introduced by scut of TESO Crew. In addition to the original three types of malformed packets, a variety of others is also included.

Building source

After getting the source tar ball, first explode the archive:
 $ tar -xvzf blip-n.n.tar.gz 
Where blip-n.n.tar.gz corresponds with the version you have.

Examine the Makefile for any system specific changes which may be required.

Run 'make' which should leave you with the 'blip' binary.

Usage

Note: Since blip can be used to forge components of the IP and UDP headers, root is required to execute the binary.

# Send query to 1.2.3.4, 2.2.2.2, and 5.6.7.8 ten times for www.yahoo.com
# IN A every 3600s
bash# ./blip -n 10 -l 3600 -h www.yahoo.com 1.2.3.4,2.2.2.2,5.6.7.8 

# Send one zlip packet type 1 to 6.6.6.6 with a spoofed source of 6.6.6.6
bash# ./blip -s 6.6.6.6 -z 1 6.6.6.6

# Flood 1.2.3.4 with random DNS packets from random sources
bash# ./blip -s 0 -R 1.2.3.4

# Send a random query type to 1.2.3.4 every second until interrupt
bash# ./blip -t 0 -n 0 1.2.3.4
Further command line arguments and features can be found by running './blip -?'

Considerations

blip is geared to run on Linux as this was the platform on and for which it was developed. There will be issues when compiling blip for different OS and architectures. Please send in patches if you are able to get it to run on different platforms.

Some empirical benchmarks are available in BENCHMARK with additional command line examples. Comparisons are also show between various stages of optimization; including switching out the standard rand() function with the "Mersenne Twister" random number generator by Makoto Matsumoto and Takuji Nishimura. Other stages of code optimization are also shown.

For more information or questions please consult the source code. =)
