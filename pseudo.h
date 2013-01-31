#ifndef PSEUDO_H
#define PSEUDO_H 1
#define PSEUDOHDRSIZE sizeof(struct pseudohdr)
struct pseudohdr
{
	unsigned long saddr;
	unsigned long daddr;
	u_char zero;
	u_char protocol;
	u_short length;
};
#endif
