/* gcc -Wall -O3 -o mitm mitm.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <pthread.h>

#define SSEC 1
#define OSEC 3
#define NSEC 5
#define CSEC 7
#define SDEL 19
#define CDEL 21
/* note if the signalling delay is longer adjust the *DEL values */

#define HNUM 2
#define HSTR 3
#define HIPA 4
#define HPRT 9
#define HADR 19
#define QUES 96
#define SLEN 196
#define BUDP 1500
#define BTCP 9500
#define BMAX 9900
#define MAGC 1337
#define MAGL 7331
#define LEET 31337

#define NOOP (0 << 0)
#define GOOD (1 << 0)
#define MAKE (1 << 1)
#define JOIN (1 << 2)
#define STOP (1 << 3)
#define TIMO (1 << 4)

#define PUDP 13
#define PTCP 15

#define HALT -1
#define INIT  0
#define PROC  1

#define MULT 4
#define SECS time(NULL)

int SEQS = 1;
int STAT = INIT;
int MAXT = 4;
int MAXC = 1003;
int HTCP = (MULT * BTCP);
int HMAX = (MULT * BMAX);
int HUGE = (MULT * LEET);
int PIPM[2];

#include "lib/rnd.c"
#include "lib/enc.c"
#include "lib/net.c"
#include "lib/inc.c"
#include "lib/key.c"

struct argp
{
	int port, lprt, fudp, ftcp;
	int eudp, etcp;
	char *mode, *addr, *ladr, *comd, *skey, *noop;
};

struct hedp
{
	unsigned char size[OFFS], xtra[OFFS];
	unsigned char indx[OFFS], prot[HPRT];
	unsigned char srcs[HADR], sprt[HPRT];
	unsigned char dsts[HADR], dprt[HPRT];
};

struct comp
{
	unsigned char size[OFFS], xtra[OFFS], indx[OFFS], prot[HSTR];
	unsigned char srcs[HIPA], sprt[HNUM], dsts[HIPA], dprt[HNUM];
};

struct conp
{
	int stat, indx, sock, prot, xtra;
	int sigs[2], totl[2], pipu[2];
	time_t last, logs[4];
	pthread_t syns;
	pthread_mutex_t lock;
	struct sockaddr_in addr;
	struct hedp head;
	struct comp coms;
	struct argp *args;
};

struct thrp
{
	int indx, zidx;
	int *sock, *socs;
	int pipr[2], pipw[2];
	char mode[5];
	struct netp *data;
	struct argp *args;
	struct conp *cons;
	struct keyp ekey, dkey;
	pthread_t thrd, thrr, thrw;
};

struct oldp
{
	int indx;
	time_t last;
};

int tcpx(int mode)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (mode == 1)
	{
		int reus = 1; setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&(reus), sizeof(int));
	}
	return sock;
}

void phed(unsigned char *comp, unsigned char *head, int indx, int tidx)
{
	head[0] = ((indx >>  8) & 0xff);
	head[1] = ((indx >>  0) & 0xff);
	head[2] = ((tidx >>  8) & 0xff);
	head[3] = ((tidx >>  0) & 0xff);
	bcopy(head, comp, 4);
}

void uhed(unsigned char *buff, int *indx, int *tidx)
{
	*indx = ((buff[0] << 8) | buff[1]);
	*tidx = ((buff[2] << 8) | buff[3]);
}

void pcom(struct hedp *head, struct comp *coms)
{
	int port;
	char *pntr, *cptr;
	cptr = (char *)head->srcs; pntr = cptr;
	for (int x = 0; x < 4; ++x)
	{
		coms->srcs[x] = atoi(pntr);
		pntr = strchr(pntr, '.');
		if (pntr == NULL) { break; }
		++pntr;
	}
	cptr = (char *)head->sprt;
	port = atoi(cptr);
	coms->sprt[1] = (port >> 0x8);
	coms->sprt[0] = (port & 0xff);
	cptr = (char *)head->dsts; pntr = cptr;
	for (int x = 0; x < 4; ++x)
	{
		coms->dsts[x] = atoi(pntr);
		pntr = strchr(pntr, '.');
		if (pntr == NULL) { break; }
		++pntr;
	}
	cptr = (char *)head->dprt;
	port = atoi(cptr);
	coms->dprt[1] = (port >> 0x8);
	coms->dprt[0] = (port & 0xff);
	bcopy(head->prot, coms->prot, 3);
}

void ucom(struct comp *coms, struct hedp *head)
{
	bcopy(coms->indx, head->indx, OFFS);
	bzero(head->srcs, HADR);
	snprintf((char *)head->srcs, HADR - 1, "%d.%d.%d.%d", coms->srcs[0], coms->srcs[1], coms->srcs[2], coms->srcs[3]);
	bzero(head->sprt, HPRT);
	snprintf((char *)head->sprt, HPRT - 1, "%d", (coms->sprt[1] << 8) | coms->sprt[0]);
	bzero(head->dsts, HADR);
	snprintf((char *)head->dsts, HADR - 1, "%d.%d.%d.%d", coms->dsts[0], coms->dsts[1], coms->dsts[2], coms->dsts[3]);
	bzero(head->dprt, HPRT);
	snprintf((char *)head->dprt, HPRT - 1, "%d", (coms->dprt[1] << 8) | coms->dprt[0]);
	bzero(head->prot, HPRT);
	bcopy(coms->prot, head->prot, 3);
}

void comd(char *path, char *addr, char *port, char *prot, char *buff, int leng)
{
	int link[2];
	if (pipe(link) < 0) { return; }
	pid_t pidn = fork();
	if (pidn == 0)
	{
		dup2(link[1], STDOUT_FILENO);
		/* dup2(link[1], STDERR_FILENO); */
		close(link[0]); close(link[1]);
		execl(path, path, addr, port, prot, NULL);
	}
	else
	{
		close(link[1]);
		waitpid(pidn, NULL, 0);
		int rlen = read(link[0], buff, leng);
		if (rlen < 1) { /* no-op */ }
		close(link[0]);
	}
}

int coma(struct conp *cons, struct sockaddr_in *news, char *prot, char *path)
{
	int leng;
	char *pros = (char *)cons->head.prot;
	char *srcs = (char *)cons->head.srcs;
	char *sprt = (char *)cons->head.sprt;
	char *dsts = (char *)cons->head.dsts;
	char *dprt = (char *)cons->head.dprt;
	char *pntr;
	char buff[SLEN];
	bcopy(prot, pros, 3);
	inet_ntop(AF_INET, &(news->sin_addr), srcs, INET_ADDRSTRLEN);
	snprintf(sprt, HPRT - 1, "%d", ntohs(news->sin_port));
	bzero(buff, SLEN);
	comd(path, srcs, sprt, prot, buff, SLEN - 11);
	if ((pntr = strchr(buff, ':')) != NULL)
	{
		*pntr = 0; leng = strlen(buff);
		if (leng < (HADR - 1))
		{
			bcopy(buff, dsts, leng); ++pntr;
			snprintf(dprt, HPRT - 1, "%d", atoi(pntr));
			pcom(&(cons->head), &(cons->coms));
			printf("%s DEST [%s] [%s:%s]->[%s:%s]\n", date(), prot, srcs, sprt, dsts, dprt);
			return 1;
		}
	}
	return -1;
}

void sets(struct conp *cons, int bits, int nots)
{
	pthread_mutex_lock(&(cons->lock));
	cons->stat |=  (bits);
	cons->stat &= ~(nots);
	pthread_mutex_unlock(&(cons->lock));
}

int stts(int stas, int bits, int nots)
{
	if (((stas & STOP) == 0) && ((stas & TIMO) == 0) && ((stas & nots) == 0))
	{
		if (((stas & JOIN) != 0) || ((stas & GOOD) != 0) || ((stas & bits) != 0))
		{
			return 1;
		}
	}
	return 0;
}

void make(struct conp *cons, struct argp *args, struct sockaddr_in *addr, char *prot, char *mode, int fdes, int tidx, int indx, int xtra, time_t nows)
{
	int pnum = PUDP;
	bcopy(addr, &(cons->addr), sizeof(struct sockaddr_in));
	if (memcmp(prot, "tcp", 3) == 0) { pnum = PTCP; }
	cons->args = args; cons->indx = tidx;
	cons->prot = pnum; cons->sock = fdes;
	cons->xtra = xtra; cons->last = nows;
	cons->stat = MAKE;
	printf("%s MAKE [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), tidx, indx, args->mode[0], mode[0], cons->head.prot, cons->head.srcs, cons->head.sprt, cons->head.dsts, cons->head.dprt, cons->sock, cons->xtra, 0, cons->stat);
}

void *syns(void *argv)
{
	struct conp *cons = (struct conp *)argv;

	int flag = fcntl(cons->sock, F_GETFL, 0);
	fcntl(cons->sock, F_SETFL, flag | O_NONBLOCK);

	int chks = connect(cons->sock, (struct sockaddr *)&(cons->addr), sizeof(cons->addr));
	if ((chks > -1) || (errno != EINPROGRESS))
	{
		sets(cons, STOP, NOOP); goto jump;
	}

	struct pollfd pfds[1];
	bzero(&(pfds), 1 * sizeof(struct pollfd));
	pfds[0].fd = cons->sock; pfds[0].events = POLLOUT;
	chks = poll(pfds, 1, NSEC * 1000);
	if ((chks > 0) && (pfds[0].revents & POLLOUT)) { /* no-op */ }
	else
	{
		sets(cons, STOP, NOOP); goto jump;
	}

	socklen_t leng = sizeof(chks);
	getsockopt(cons->sock, SOL_SOCKET, SO_ERROR, &(chks), &(leng));
	if (chks != 0)
	{
		sets(cons, STOP, NOOP); goto jump;
	}

	fcntl(cons->sock, F_SETFL, flag);

	int erro;
	unsigned char buff[1];
	cons->xtra = MAGL;

jump:
	printf("%s SYNS [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), "tcp", cons->head.srcs, cons->head.sprt, cons->head.dsts, cons->head.dprt, cons->sock, cons->xtra, 0, cons->stat);
	sets(cons, JOIN, NOOP);
	erro = write(cons->sigs[0], buff, 1);
	if (erro < 0) { /* no-op */ }
	erro = write(cons->sigs[1], buff, 1);
	if (erro < 0) { /* no-op */ }

	return NULL;
}

int recp(int sock, unsigned char *buff, int leng)
{
	int rlen, zlen = 0, slen = 2, size = 0;
	unsigned char data[2];
	unsigned char *pntr = data;
	while (size < slen)
	{
		rlen = read(sock, pntr, slen - size);
		if (rlen < 1) { return 0; }
		pntr += rlen; size += rlen;
		if ((size > 1) && (zlen < 1))
		{
			pntr = buff; size = 0;
			zlen = ((data[1] << 8) | data[0]); slen = zlen;
			if (zlen > leng) { return 0; }
		}
	}
	return zlen;
}

void senp(int sock, unsigned char *buff, int leng)
{
	buff[1] = (leng >> 8); buff[0] = (leng & 0xff);
	leng += 2;
	int erro = write(sock, buff, leng);
	if (erro < 1) { /* no-op */ }
}

void *thrw(void *argv)
{
	struct thrp *thrs = (struct thrp *)argv;
	struct argp *args = thrs->args;
	struct conp *cons = thrs->cons;

	int MAXF = (MAXT * MAXC);

	int erro;
	int indx, tidx, fdes, sock;
	int pidx, leng, plen, clen;
	int xtra, loop;
	int hlen = sizeof(struct comp);
	int slen = sizeof(struct sockaddr_in);
	int ridx[MAXF];
	char *dptr, *eptr;
	unsigned char buff[HUGE], encr[HUGE];
	unsigned char *pntr;
	struct pollfd pfds[MAXF];
	struct sockaddr_in serv;
	struct sockaddr_in *padr;
	struct conp *cptr;
	struct comp coms;
	struct netp *pdat;
	time_t nows;

	printf("%s THRW [%d] [%c][%c] [%d]\n", date(), thrs->indx, args->mode[0], thrs->mode[0], *(thrs->sock));

	while (1)
	{
		if (STAT == INIT) { sleep(1); continue; }
		if (STAT == HALT) { break; }

		if (((*(thrs->sock)) < 1) || (thrs->pipr[0] < 1) || (thrs->pipw[0] < 1)) { STAT = HALT; printf("HALT <0>\n"); break; }

		if (thrs->mode[0] == 'r')
		{
			bzero(&(pfds), MAXF * sizeof(struct pollfd));
			bzero(&(ridx), MAXF * sizeof(int));
			pidx = 0; pfds[pidx].fd = thrs->pipr[0]; pfds[pidx].events = POLLIN; ++pidx;
			for (int x = 1; x < MAXC; ++x)
			{
				indx = x; cptr = &(cons[indx]);
				if ((cptr->indx == thrs->indx) && (stts(cptr->stat, NOOP, NOOP) != 0))
				{
					if (cptr->sock > 0)
					{
						ridx[indx] = pidx; pfds[pidx].fd = cptr->sock; pfds[pidx].events = POLLIN; ++pidx;
					}
				}
			}

			erro = poll(pfds, pidx, SSEC * 1000);
			nows = SECS;

			if (pfds[0].revents & POLLIN)
			{
				erro = read(thrs->pipr[0], buff, 1);
			}

			for (int x = 1; x < MAXC; ++x)
			{
				indx = x; cptr = &(cons[indx]);
				plen = 0; leng = 0; xtra = 0;
				pidx = ridx[indx];

				if ((cptr->indx == thrs->indx) && (stts(cptr->stat, MAKE, NOOP) != 0))
				{
					if (cptr->sock > 0)
					{
						if ((pfds[pidx].revents & POLLNVAL) || (pfds[pidx].revents & POLLERR) || (pfds[pidx].revents & POLLHUP))
						{
							printf("%s EPOL [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->stat);
							pntr = (buff + hlen); plen = hlen;
							leng = 1;
							xtra = MAGC;
						}
					}
					if ((plen < 1) && (cptr->xtra == MAGL))
					{
						if (cptr->prot != NOOP)
						{
							pntr = (buff + hlen); plen = hlen;
							leng = 1;
							xtra = MAGL;
						}
					}
					if ((plen < 1) && ((cptr->stat & MAKE) == 0) && (cptr->sock > 0) && (pfds[pidx].revents & POLLIN))
					{
						if (cptr->prot == PUDP)
						{
							if (args->mode[0] == 'c')
							{
								pntr = (buff + hlen); plen = hlen;
								leng = recp(cptr->sock, pntr, BUDP);
							}
							if (args->mode[0] == 's')
							{
								pntr = (buff + hlen); plen = hlen;
								slen = sizeof(struct sockaddr_in);
								leng = recvfrom(cptr->sock, pntr, BUDP, 0, (struct sockaddr *)&(serv), (socklen_t *)&(slen));
							}
						}
						if (cptr->prot == PTCP)
						{
							pntr = (buff + hlen); plen = hlen;
							leng = recv(cptr->sock, pntr, HTCP, 0);
						}
					}
				}
				if (plen > 0)
				{
					bcopy(&(cptr->coms), &(coms), hlen);
					if (xtra == MAGL)
					{
						if (args->mode[0] == 'c')
						{
							if ((cptr->stat & MAKE) != 0)
							{
								cptr->xtra = NOOP;
							}
							else
							{
								cptr->xtra = NOOP;
								printf("%s WFIN [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->stat);
							}
						}
						if (args->mode[0] == 's')
						{
							if ((cptr->stat & MAKE) != 0)
							{
								cptr->xtra = NOOP;
								sets(cptr, GOOD, MAKE);
								printf("%s GOOD [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng);
							}
							else
							{
								cptr->xtra = NOOP;
								printf("%s WFIN [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->stat);
							}
						}
					}
					if (xtra == 0)
					{
						if (leng > 0)
						{
							cptr->totl[0] += 1;
							if (cptr->totl[0] <= 5)
							{
								printf("%s READ [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [~%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->totl[0]);
								cptr->logs[0] = nows;
							}
							else if ((nows - cptr->logs[0]) >= OSEC) { cptr->totl[0] = 0; }
						}
						else
						{
							xtra = MAGC;
							leng = 1;
							printf("%s ELEN [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng);
						}
					}

					plen += leng;
					pack(coms.size, plen);
					pack(coms.xtra, xtra);
					bcopy(&(coms), buff, hlen);
					clen = plen; pntr = buff;

					if (args->noop == NULL)
					{
						pntr = (encr + OFFS);
						clen = ciph(pntr, buff, plen, &(thrs->ekey), 'e');
						clen = (clen + OFFS); pack(encr, clen);
						pntr = encr;
					}

					sall(*(thrs->sock), pntr, clen);
					cptr->last = nows;

					if (xtra == MAGC)
					{
						sets(cptr, STOP, NOOP);
						erro = write(PIPM[1], buff, 1);
					}
				}
			}
		}

		if (thrs->mode[0] == 'w')
		{
			bzero(&(pfds), MAXF * sizeof(struct pollfd));
			pfds[0].fd = thrs->pipw[0]; pfds[0].events = POLLIN;
			pfds[1].fd = *(thrs->sock); pfds[1].events = POLLIN;

			erro = poll(pfds, 2, SSEC * 1000);
			nows = SECS;

			if (pfds[0].revents & POLLIN)
			{
				erro = read(thrs->pipw[0], buff, 1);
			}

			if (pfds[1].revents & POLLIN)
			{
				for (loop = 0; loop > -1; ++loop)
				{
					pdat = thrs->data;
					erro = rall(*(thrs->sock), loop, pdat);
					pntr = pdat->buff;
					if (erro == 0) { break; }
					if (erro < 0) { STAT = HALT; printf("HALT <3> %d\n", erro); break; }

					if (args->noop == NULL)
					{
						pntr = (pntr + OFFS);
						plen = (erro - OFFS);
						clen = ciph(encr, pntr, plen, &(thrs->dkey), 'd');
						if (clen < 1) { STAT = HALT; printf("HALT <30> %d %d\n", erro, clen); break; }
						pntr = encr;
					}

					bcopy(pntr, &(coms), hlen);
					unpk(coms.size, &(plen));
					unpk(coms.xtra, &(xtra));
					uhed(coms.indx, &(indx), &(tidx));
					leng = (plen - hlen);
					pntr = (pntr + hlen);

					if ((leng > HTCP) || (indx > (MAXC - 1)) || (tidx > MAXT))
					{
						STAT = HALT; printf("HALT <4> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); break;
					}

					cptr = &(cons[indx]);

					if (xtra == MAGC)
					{
						if ((memcmp(coms.prot, cptr->coms.prot, 3) == 0) && (memcmp(coms.srcs, cptr->coms.srcs, HIPA) == 0) && (memcmp(coms.sprt, cptr->coms.sprt, HNUM) == 0) && (memcmp(coms.dsts, cptr->coms.dsts, HIPA) == 0) && (memcmp(coms.dprt, cptr->coms.dprt, HNUM) == 0))
						{
							if (stts(cptr->stat, NOOP, NOOP) != 0)
							{
								printf("%s STOP [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng);
								sets(cptr, STOP, NOOP);
								erro = write(PIPM[1], buff, 1);
							}
							else if ((cptr->stat & STOP) != 0)
							{
								if ((nows - cptr->logs[3]) >= OSEC)
								{
									printf("%s WEND [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [x%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->totl[1]);
									cptr->logs[3] = nows;
								}
							}
							else if ((cptr->stat & MAKE) != 0)
							{
								printf("%s WNEW [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng);
								sets(cptr, STOP, NOOP);
								erro = write(PIPM[1], buff, 1);
							}
							else { /*STAT = HALT;*/ printf("HALT <5> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); /*break;*/ }
						}
						else { /*STAT = HALT;*/ printf("HALT <6> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); /*break;*/ }
					}
					else if (xtra == MAGL)
					{
						if (args->mode[0] == 'c')
						{
							if ((cptr->stat & MAKE) != 0)
							{
								cptr->xtra = NOOP;
								sets(cptr, GOOD, MAKE);
								printf("%s GOOD [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng);
							}
							else
							{
								printf("%s WMAG [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->stat);
							}
						}
						if (args->mode[0] == 's')
						{
							if (cptr->stat == NOOP)
							{
								bcopy(&(coms), &(cptr->coms), hlen);
								ucom(&(cptr->coms), &(cptr->head));
								dptr = (char *)cptr->head.dprt;
								eptr = (char *)cptr->head.dsts;
								bzero(&(serv), sizeof(struct sockaddr_in));
								serv.sin_family = AF_INET;
								serv.sin_port = htons(atoi(dptr));
								serv.sin_addr.s_addr = inet_addr(eptr);
								if (memcmp(coms.prot, "udp", 3) == 0)
								{
									fdes = socket(AF_INET, SOCK_DGRAM, 0);
									make(cptr, args, &(serv), "udp", thrs->mode, fdes, tidx, indx, MAGL, nows);
									erro = write(thrs->pipr[1], buff, 1);
									erro = write(thrs->pipw[1], buff, 1);
									printf("%s SYNS [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), "udp", cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, 0, cptr->stat);
								}
								if (memcmp(coms.prot, "tcp", 3) == 0)
								{
									fdes = tcpx(1);
									make(cptr, args, &(serv), "tcp", thrs->mode, fdes, tidx, indx, NOOP, nows);
									cptr->sigs[0] = thrs->pipr[1];
									cptr->sigs[1] = thrs->pipw[1];
									pthread_create(&(cptr->syns), NULL, syns, cptr);
								}
							}
							else
							{
								printf("%s WMAG [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->stat);
							}
						}
					}
					else if (leng > 0)
					{
						if (cptr->stat == NOOP)
						{
							/*STAT = HALT;*/ printf("HALT <9> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); /*break;*/
						}
						else if ((tidx != thrs->indx) || (thrs->indx != cptr->indx))
						{
							STAT = HALT; printf("HALT <10> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); break;
						}
						else if ((cptr->stat & MAKE) != 0)
						{
							printf("%s DROP [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [x%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->totl[1]);
						}
						else if (stts(cptr->stat, NOOP, NOOP) != 0)
						{
							sock = cptr->sock;
							if (cptr->prot == PUDP)
							{
								padr = &(cptr->addr);
								if (args->mode[0] == 'c')
								{
									sock = args->fudp;
								}
								sendto(sock, pntr, leng, 0, (struct sockaddr *)padr, sizeof(struct sockaddr_in));
							}
							if (cptr->prot == PTCP)
							{
								sall(sock, pntr, leng);
							}
							cptr->last = nows;
							cptr->totl[1] += 1;
							if (cptr->totl[1] <= 5)
							{
								printf("%s SEND [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [~%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->totl[1]);
								cptr->logs[1] = nows;
							}
							else if ((nows - cptr->logs[1]) >= OSEC) { cptr->totl[1] = 0; }
						}
						else if ((cptr->stat & STOP) != 0)
						{
							if ((nows - cptr->logs[2]) >= OSEC)
							{
								printf("%s WLEN [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d] [%d][%d] [x%d]\n", date(), thrs->indx, indx, args->mode[0], thrs->mode[0], cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, cptr->sock, cptr->xtra, leng, cptr->totl[1]);
								cptr->logs[2] = nows;
							}
						}
						else { STAT = HALT; printf("HALT <11> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); break; }
					}
					else { STAT = HALT; printf("HALT <12> %d %d %d %d %d\n", erro, tidx, indx, xtra, leng); break; }
				}
			}
		}
	}

	return NULL;
}

void *thrd(void *argv)
{
	struct thrp *thrs = (struct thrp *)argv;
	struct argp *args = thrs->args;

	struct thrp thor, thow;
	struct keyp skey;
	struct sockaddr_in serv;

	if (args->mode[0] == 'c')
	{
		while (thrs->indx != SEQS) { usleep(357000); }
		*(thrs->sock) = tcpx(0);
		serv.sin_family = AF_INET;
		serv.sin_port = htons(args->port);
		inet_pton(AF_INET, args->addr, &(serv.sin_addr));
		if (connect(*(thrs->sock), (struct sockaddr *)&(serv), sizeof(struct sockaddr_in)) != 0)
		{
			printf("%s CONC [%s][%d] [%d][%d]\n", date(), args->addr, args->port, thrs->indx, *(thrs->sock));
			exit(1);
		}
		skey = xchg(*(thrs->sock), args->skey, 'c', thrs->indx);
		if (skey.klen < 1)
		{
			printf("%s CKEY [%s][%d] [%d][%d]\n", date(), args->addr, args->port, thrs->indx, *(thrs->sock));
			exit(1);
		}
		printf("%s CLIE [%s][%d] [%d][%d]\n", date(), args->addr, args->port, thrs->indx, *(thrs->sock));
		SEQS += 1;
	}

	if (args->mode[0] == 's')
	{
		int zidx = thrs->zidx;
		skey = xchg(thrs->socs[zidx], args->skey, 's', thrs->indx);
		if (skey.klen < 1)
		{
			if (thrs->indx < 2)
			{
				printf("%s SKEY [%s][%d] [%d][%d]\n", date(), args->ladr, args->lprt, thrs->indx, thrs->socs[zidx]);
				fins(&(thrs->socs[zidx]));
				return NULL;
			}
			else
			{
				printf("%s SIDX [%s][%d] [%d][%d]\n", date(), args->ladr, args->lprt, thrs->indx, thrs->socs[zidx]);
				exit(1);
			}
		}
		else
		{
			*(thrs->sock) = thrs->socs[zidx];
		}
		printf("%s SERV [%s][%d] [%d][%d]\n", date(), args->ladr, args->lprt, thrs->indx, *(thrs->sock));
		SEQS += 1;
	}

	bcopy(&(skey), &(thrs->ekey), sizeof(struct keyp));
	bcopy(&(skey), &(thrs->dkey), sizeof(struct keyp));

	bcopy(thrs, &(thor), sizeof(struct thrp));
	thor.mode[0] = 'r';
	bzero(&(thor.thrr), sizeof(pthread_t));
	pthread_create(&(thor.thrr), NULL, thrw, &(thor));

	bcopy(thrs, &(thow), sizeof(struct thrp));
	thow.mode[0] = 'w';
	bzero(&(thow.thrw), sizeof(pthread_t));
	pthread_create(&(thow.thrw), NULL, thrw, &(thow));

	if ((thrs->indx == MAXT) && (STAT == INIT))
	{
		STAT = PROC;
	}

	pthread_join(thor.thrr, NULL);
	pthread_join(thow.thrw, NULL);

	return NULL;
}

void *mgmt(void *argv)
{
	struct conp **cons = (struct conp **)argv;
	struct argp *args = cons[0][0].args;

	int erro, indx, sock, prot, dprt, expr;
	int omax, olen, tlen, osub = 31, olim = ((MAXC * 3) / 9);
	int redo = (args->mode[0] == 'c') ? CDEL : SDEL;
	int ulow = 15, mlow = 15;
	int udpl[] = { 53 };
	int lenu = (sizeof(udpl) / sizeof(udpl[0]));
	char outs[BUDP], line[BUDP];
	unsigned char buff[HUGE];
	time_t nows, last, logs;
	struct pollfd pfds[1];
	struct conp *cptr;
	struct oldp olds[MAXC + MAXC];

	logs = 0;
	olim = (olim + ((olim + 1) % 2));

	while (1)
	{
		if (STAT == INIT) { sleep(1); continue; }
		if (STAT == HALT) { break; }

		bzero(&(pfds), 1 * sizeof(struct pollfd));
		pfds[0].fd = PIPM[0]; pfds[0].events = POLLIN;

		erro = poll(pfds, 1, 357);
		nows = SECS;

		if (pfds[0].revents & POLLIN)
		{
			erro = read(PIPM[0], buff, 1);
			if (erro < 0) { /* no-op */ }
		}

		bzero(outs, BUDP);
		snprintf(outs, BUDP - SUBS, "%s MGMT", date());
		for (int x = 0; x < MAXT; ++x)
		{
			tlen = 0; olen = 0; bzero(&(olds), MAXC * sizeof(struct oldp));
			for (int y = 1; y < MAXC; ++y)
			{
				cptr = &(cons[x][y]);
				indx = cptr->indx;
				sock = cptr->sock;
				last = cptr->last;
				prot = cptr->prot;
				dprt = ((cptr->coms.dprt[1] << 8) | cptr->coms.dprt[0]);
				expr = (prot == PUDP) ? args->eudp : args->etcp;
				if (stts(cptr->stat, NOOP, NOOP) != 0)
				{
					for (int z = 0; z < lenu; ++z)
					{
						if ((prot == PUDP) && (dprt == udpl[z]))
						{
							expr = ulow; break;
						}
					}
					if ((nows - last) > expr)
					{
						sets(cptr, STOP, NOOP);
						printf("%s EXPR [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d] [%d] [%d][%d]\n", date(), indx, y, cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, sock, cptr->xtra, redo, expr);
					}
				}
				if ((cptr->stat & JOIN) != 0)
				{
					if (cptr != NULL)
					{
						pthread_join(cptr->syns, NULL);
						sets(cptr, NOOP, JOIN);
						printf("%s JOIN [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d] [%d] [%d][%d]\n", date(), indx, y, cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, sock, cptr->xtra, redo, expr);
					}
				}
				if ((cptr->stat & TIMO) != 0)
				{
					if ((nows - last) >= redo)
					{
						printf("%s ZERO [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d] [%d] [%d][%d]\n", date(), indx, y, cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, sock, cptr->xtra, redo, expr);
						erro = pipe(cptr->pipu);
						pthread_mutex_unlock(&(cptr->lock));
						bzero(&(cptr->coms), sizeof(struct comp));
						bzero(&(cptr->head), sizeof(struct hedp));
						bzero(&(cptr->addr), sizeof(struct sockaddr_in));
						bzero(&(cptr->syns), sizeof(pthread_t));
						bzero(cptr->logs, 4 * sizeof(time_t)); cptr->last = 0;
						bzero(cptr->totl, 2 * sizeof(int));
						bzero(cptr->sigs, 2 * sizeof(int));
						cptr->xtra = 0; cptr->prot = 0; cptr->sock = 0; cptr->indx = 0;
						cptr->stat = NOOP;
					}
				}
				if ((cptr->stat & STOP) != 0)
				{
					if ((cptr->stat & TIMO) == 0)
					{
						printf("%s FINS [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d] [%d] [%d][%d]\n", date(), indx, y, cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, sock, cptr->xtra, redo, expr);
						if (cptr->sock != cptr->pipu[0]) { fins(&(cptr->sock)); }
						close(cptr->pipu[0]); close(cptr->pipu[1]);
						sets(cptr, TIMO, NOOP);
						cptr->last = nows;
					}
				}
				if ((cptr->stat & MAKE) != 0)
				{
					if ((nows - last) > mlow)
					{
						sets(cptr, STOP, NOOP);
						printf("%s ENEW [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d] [%d] [%d][%d]\n", date(), indx, y, cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, sock, cptr->xtra, redo, expr);
					}
				}
				if (cptr->stat != NOOP)
				{
					if (cptr->prot == PUDP)
					{
						omax = (olen + 1);
						for (int z = 0; z < omax; ++z)
						{
							if ((z == olen) || (cptr->last < olds[z].last))
							{
								for (int w = omax; w > z; --w) { olds[w].indx = olds[w-1].indx; olds[w].last = olds[w-1].last; }
								olds[z].indx = y; olds[z].last = cptr->last;
								++olen; break;
							}
						}
					}
					if (cptr->prot == PTCP)
					{
						++tlen;
					}
				}
			}
			if ((nows - logs) >= (OSEC + OSEC))
			{
				bzero(line, BUDP);
				snprintf(line, BUDP - SUBS, " %s[IDX:%d~UDP:%d~TCP:%d]", (x == 0) ? "" : "| ", x + 1, olen, tlen);
				strcat(outs, line);
			}
			if (olen >= olim)
			{
				for (int z = 0; z < (olen - (olim - osub)); ++z)
				{
					int y = olds[z].indx;
					cptr = &(cons[x][y]);
					printf("%s OLDS [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d] [%d] [%d][%d]\n", date(), indx, y, cptr->head.prot, cptr->head.srcs, cptr->head.sprt, cptr->head.dsts, cptr->head.dprt, sock, cptr->xtra, redo, expr);
					sets(cptr, STOP, NOOP);
				}
			}
		}

		if ((nows - logs) >= (OSEC + OSEC))
		{
			bzero(line, BUDP);
			snprintf(line, BUDP - SUBS, " [%d][%d]", osub, olim);
			strcat(outs, line);
			printf("%s\n", outs);
			logs = nows;
		}
	}

	return NULL;
}

void serv(struct argp *args)
{
	int erro, reus, leng, fdes;
	int slen = sizeof(struct sockaddr_in);
	struct sockaddr_in sudp, stcp, news;
	struct sockaddr_in *sptr;

	sptr = &(sudp);
	bzero(sptr, slen);
	sptr->sin_family = AF_INET;
	sptr->sin_port = htons(args->lprt);
	sptr->sin_addr.s_addr = inet_addr(args->ladr);
	args->fudp = socket(AF_INET, SOCK_DGRAM, 0);
	reus = 1; setsockopt(args->fudp, SOL_SOCKET, SO_REUSEADDR, (char *)&(reus), sizeof(int));
	reus = 1; setsockopt(args->fudp, SOL_SOCKET, SO_REUSEPORT, (char *)&(reus), sizeof(reus));
	erro = bind(args->fudp, (struct sockaddr *)sptr, slen); if (erro < 0) { printf("BIND UDP\n"); exit(1); }

	sptr = &(stcp);
	bzero(sptr, slen);
	sptr->sin_family = AF_INET;
	sptr->sin_port = htons(args->lprt);
	sptr->sin_addr.s_addr = inet_addr(args->ladr);
	if (args->mode[0] == 'c') { args->ftcp = tcpx(1); } else { args->ftcp = tcpx(0); }
	reus = 1; setsockopt(args->ftcp, SOL_SOCKET, SO_REUSEADDR, (char *)&(reus), sizeof(int));
	reus = 1; setsockopt(args->ftcp, SOL_SOCKET, SO_REUSEPORT, (char *)&(reus), sizeof(int));
	erro = bind(args->ftcp, (struct sockaddr *)sptr, slen); if (erro < 0) { printf("BIND TCP\n"); exit(1); }
	listen(args->ftcp, QUES);

	struct conp *cptr;
	struct conp **cons = malloc(MAXT * sizeof(struct conp *));
	for (int x = 0; x < MAXT; ++x)
	{
		cons[x] = malloc(MAXC * sizeof(struct conp));
		bzero(cons[x], MAXC * sizeof(struct conp));
		for (int y = 0; y < MAXC; ++y)
		{
			cons[x][y].args = args;
			erro = pipe(cons[x][y].pipu);
			pthread_mutex_init(&(cons[x][y].lock), NULL);
		}
	}

	erro = pipe(PIPM);
	if (erro < 0) { /* no-op */ }

	struct thrp tmps[MAXC];
	int *socs = malloc(MAXC * sizeof(int));
	bzero(socs, MAXC * sizeof(int));
	struct thrp *thrs = malloc(MAXT * sizeof(struct thrp));
	bzero(thrs, MAXT * sizeof(struct thrp));
	for (int x = 0; x < MAXT; ++x)
	{
		thrs[x].indx = (x + 1); thrs[x].args = args; thrs[x].cons = cons[x];
		erro = pipe(thrs[x].pipr); erro = pipe(thrs[x].pipw);
		thrs[x].sock = malloc(1 * sizeof(int)); thrs[x].sock[0] = 0;
		thrs[x].socs = socs;
		thrs[x].data = neti(HUGE);
		if (args->mode[0] == 'c')
		{
			bzero(&(thrs[x].thrd), sizeof(pthread_t));
			pthread_create(&(thrs[x].thrd), NULL, thrd, &(thrs[x]));
		}
	}

	pthread_t thrm;
	bzero(&(thrm), sizeof(pthread_t));
	pthread_create(&(thrm), NULL, mgmt, cons);

	int indx, indy, fidx, fidy, zidx = 0;
	unsigned char buff[HUGE];
	unsigned char *pntr;
	struct pollfd pfds[MAXT];
	time_t nows;
	while (1)
	{
		if (STAT == HALT) { break; }

		bzero(&(pfds), MAXT * sizeof(struct pollfd));
		pfds[0].fd = args->fudp; pfds[0].events = POLLIN;
		pfds[1].fd = args->ftcp; pfds[1].events = POLLIN;

		erro = poll(pfds, 2, SSEC * 1000);
		nows = SECS;

		if (args->mode[0] == 's')
		{
			if (pfds[1].revents & POLLIN)
			{
				slen = sizeof(struct sockaddr_in);
				fdes = accept(args->ftcp, (struct sockaddr *)&(news), (socklen_t *)&(slen));

				if (fdes > 0)
				{
					for (int x = 0; x < MAXT; ++x)
					{
						if (*(thrs[x].sock) < 1)
						{
							if (zidx < MAXC)
							{
								socs[zidx] = fdes;
								printf("%s ACCP tcp [%d][%d]\n", date(), zidx, fdes);
								bcopy(&(thrs[x]), &(tmps[zidx]), sizeof(struct thrp));
								tmps[zidx].zidx = zidx;
								pthread_create(&(tmps[zidx].thrd), NULL, thrd, &(tmps[zidx]));
								fdes = -1; ++zidx;
							}
							else
							{
								STAT = HALT; printf("%s ZIDX tcp [%d][%d]\n", date(), zidx, fdes); exit(1);
							}
							break;
						}
					}
					if (fdes > 0)
					{
						printf("%s FDES tcp [%s:%d] [%d]\n", date(), inet_ntoa(news.sin_addr), ntohs(news.sin_port), fdes);
						fins(&(fdes));
					}
				}
			}
		}

		if (STAT == INIT) { sleep(1); continue; }

		if (args->mode[0] == 'c')
		{
			if (pfds[0].revents & POLLIN)
			{
				pntr = (buff + 2);
				slen = sizeof(struct sockaddr_in);
				leng = recvfrom(args->fudp, pntr, BUDP, 0, (struct sockaddr *)&(news), (socklen_t *)&(slen));

				if (leng > 0)
				{
					indx = -1; indy = -1; fidx = -1; fidy = -1;
					slen = sizeof(struct sockaddr_in);
					for (int y = 1; y < MAXC; ++y)
					{
						for (int x = 0; x < MAXT; ++x)
						{
							cptr = &(cons[x][y]);
							if ((stts(cptr->stat, MAKE, NOOP) != 0) && (memcmp(&(cptr->addr), &(news), slen) == 0))
							{
								indx = x; indy = y;
							}
							if ((cptr->stat == NOOP) && (fidy < 0))
							{
								fidx = x; fidy = y;
							}
						}
					}
					if ((indy < 1) && (fidy > 0))
					{
						cptr = &(cons[fidx][fidy]);
						if (coma(cptr, &(news), "udp", args->comd) > 0)
						{
							zidx = (fidx + 1);
							fdes = cptr->pipu[0];
							phed(cptr->coms.indx, cptr->head.indx, fidy, zidx);
							make(cptr, args, &(news), "udp", "r", fdes, zidx, fidy, MAGL, nows);
							indx = fidx; indy = fidy;
						}
						else
						{
							printf("%s WDST udp [%s:%d] [%d]\n", date(), inet_ntoa(news.sin_addr), ntohs(news.sin_port), leng);
						}
					}
					if (indy > 0)
					{
						cptr = &(cons[indx][indy]);
						zidx = cptr->indx;
						if (stts(cptr->stat, MAKE, NOOP) != 0)
						{
							senp(cptr->pipu[1], buff, leng);
							erro = write(thrs[zidx - 1].pipr[1], buff, 1);
						}
						else
						{
							printf("%s DROP udp [%s:%d] [%d]\n", date(), inet_ntoa(news.sin_addr), ntohs(news.sin_port), leng);
						}
					}
					else
					{
						printf("%s INDX udp [%s:%d] [%d]\n", date(), inet_ntoa(news.sin_addr), ntohs(news.sin_port), leng);
					}
				}
			}

			if (pfds[1].revents & POLLIN)
			{
				slen = sizeof(struct sockaddr_in);
				fdes = accept(args->ftcp, (struct sockaddr *)&(news), (socklen_t *)&(slen));

				if (fdes > 0)
				{
					fidx = -1; fidy = -1;
					slen = sizeof(struct sockaddr_in);
					for (int y = 1; y < MAXC; ++y)
					{
						for (int x = 0; x < MAXT; ++x)
						{
							if (cons[x][y].stat == NOOP) { fidx = x; fidy = y; break; }
						}
						if (fidy > 0) { break; }
					}
					if (fidy > 0)
					{
						cptr = &(cons[fidx][fidy]);
						if (coma(cptr, &(news), "tcp", args->comd) > 0)
						{
							zidx = (fidx + 1);
							phed(cptr->coms.indx, cptr->head.indx, fidy, zidx);
							make(cptr, args, &(news), "tcp", "r", fdes, zidx, fidy, MAGL, nows);
							erro = write(thrs[zidx - 1].pipr[1], buff, 1);
						}
						else
						{
							printf("%s WDST tcp [%s:%d] [%d]\n", date(), inet_ntoa(news.sin_addr), ntohs(news.sin_port), fdes);
							fins(&(fdes));
						}
					}
					else
					{
						printf("%s INDX tcp [%s:%d] [%d]\n", date(), inet_ntoa(news.sin_addr), ntohs(news.sin_port), fdes);
						fins(&(fdes));
					}
				}
			}
		}
	}
}

void sige(int s)
{
	printf("INTR\n");
	exit(0);
}

void sigp(int s)
{
	printf("PIPE\n");
}

void sigs()
{
	signal(SIGINT, sige);
	signal(SIGPIPE, SIG_IGN);
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

int main(int argc, char **argv)
{
	char *pntr;
	struct argp args;
	bzero(&(args), sizeof(struct argp));

	for (int x = 1; x < argc; ++x)
	{
		if (strcmp(argv[x], "-c") == 0) { if ((x+1) < argc) { args.comd = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-m") == 0) { if ((x+1) < argc) { args.mode = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-l") == 0) { if ((x+1) < argc) { args.ladr = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-r") == 0) { if ((x+1) < argc) { args.addr = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-k") == 0) { if ((x+1) < argc) { args.skey = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-n") == 0) { if ((x+1) < argc) { args.noop = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-u") == 0) { if ((x+1) < argc) { args.eudp = atoi(argv[x+1]); } }
		if (strcmp(argv[x], "-t") == 0) { if ((x+1) < argc) { args.etcp = atoi(argv[x+1]); } }
		if (strcmp(argv[x], "-z") == 0) { if ((x+1) < argc) { MAXT = atoi(argv[x+1]); } }
	}

	if (args.comd == NULL) { args.comd = strdup(" "); }
	if (args.mode == NULL) { args.mode = strdup(" "); }
	if (args.ladr == NULL) { args.ladr = strdup(" "); }
	if (args.addr == NULL) { args.addr = strdup(" "); }
	if (args.skey == NULL) { args.skey = strdup(" "); }
	if (args.eudp < 5) { args.eudp = 35; }
	if (args.etcp < 5) { args.etcp = 95000; }

	HUGE = (MULT * HMAX);

	if ((pntr = strchr(args.ladr, ':')) != NULL)
	{
		*pntr = 0; ++pntr;
		args.lprt = atoi(pntr);
	}

	if ((pntr = strchr(args.addr, ':')) != NULL)
	{
		*pntr = 0; ++pntr;
		args.port = atoi(pntr);
	}

	if ((pntr = getenv("SKEY")) != NULL)
	{
		printf("%s ENVS [%c][%ld]\n", date(), pntr[0], strlen(pntr));
		args.skey = strdup(pntr);
	}

	sigs();
	setvbuf(stdout, NULL, _IONBF, 0);
	unsigned int inir = srnd();

	printf("%s INIT [%08x] [%d][%d] [%d][%d] [%d][%d] [%p]\n", date(), inir, args.eudp, args.etcp, MAXT, MAXC, HTCP, HUGE, args.noop);
	serv(&(args));

	return 0;
}
