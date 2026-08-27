/* gcc -Wall -O3 -fPIC -shared -o net.o lib/net.c */

#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define SUBS 8
#define OFFS 4
#define BONE 1
#define ZERO 0

struct netp
{
	int leng, size, maxb;
	unsigned char *buff, *hold;
};

int LIST = 16;

void uadr(char **pntr, int *port, char *inpt)
{
	char *temp = strchr(inpt, ':');
	*pntr = inpt; *port = 0;
	if (temp)
	{
		*temp = 0; ++temp;
		*pntr = inpt;
		*port = atoi(temp);
	}
}

void pack(unsigned char *buff, int leng)
{
	buff[0] = ((ZERO >> 24) & 0xff);
	buff[1] = ((leng >> 16) & 0xff);
	buff[2] = ((leng >>  8) & 0xff);
	buff[3] = ((leng >>  0) & 0xff);
}

void unpk(unsigned char *buff, int *leng)
{
	*leng = ((buff[1] << 16) | (buff[2] <<  8) | (buff[3] <<  0));
}

void fins(int *sock)
{
	if (*sock > 1)
	{
		shutdown(*sock, SHUT_RDWR);
		close(*sock);
	}
	*sock = -1;
}

struct netp *neti(int size)
{
	struct netp *objc = malloc(1 * sizeof(struct netp));
	bzero(objc, 1 * sizeof(struct netp));
	objc->maxb = (size - SUBS);
	objc->buff = malloc(size * sizeof(unsigned char));
	objc->hold = malloc(size * sizeof(unsigned char));
	return objc;
}

int rall(int sock, int mode, struct netp *data)
{
	int leng, size, left;
	unsigned char *pntr;
	if (mode == 0)
	{
		size = (data->maxb - data->leng);
		if (size < BONE) { return -1; }
		pntr = (data->hold + data->leng);
		leng = recv(sock, pntr, size, 0);
		if (leng < BONE) { return -2; }
		data->leng += leng;
	}
	if ((data->size < BONE) && (data->leng >= OFFS))
	{
		unpk(data->hold, &(data->size));
		size = data->maxb;
		if (data->size <= OFFS) { return -3; }
		if (data->size >= size) { return -4; }
	}
	if ((data->size > ZERO) && (data->leng >= data->size))
	{
		size = data->size;
		bcopy(data->hold, data->buff, size);
		left = (data->leng - size);
		pntr = (data->hold + size);
		for (int x = 0; x < left; ++x) { data->hold[x] = pntr[x]; }
		data->size = ZERO;
		data->leng = left;
		return size;
	}
	return 0;
}

int sall(int sock, unsigned char *buff, int leng)
{
	int wlen;
	if (sock < 1) { return -1; }
	if (leng < 1) { return -2; }
	while (leng > 0)
	{
		wlen = send(sock, buff, leng, 0);
		if (wlen < 0) { return -3; }
		buff += wlen; leng -= wlen;
	}
	return 1;
}
