#!/usr/bin/python3

import os, sys, time
import select, socket, subprocess
import argparse, ipaddress, threading
import ctypes, random, string
import copy, functools, struct
import traceback

print = functools.partial(print, flush=True)

ZSEC = 0
SSEC = 1
OSEC = 3
NSEC = 5
SDEL = 11
CDEL = 19

OFFS = 4
SUBS = 8
QUES = 96
BLEN = 196
BUDP = 1500
BTCP = 9500
BMAX = 9900
MAGC = 1337
MAGL = 31337

NOOP = (0 << 0)
GOOD = (1 << 0)
MAKE = (1 << 1)
JOIN = (1 << 2)
STOP = (1 << 3)
TIMO = (1 << 4)

PUDP = 13
PTCP = 15

HALT = -1
INIT =  0
PROC =  1

LIMI = 1001

SEQS = 1
STAT = INIT
MAXT = 4
MAXC = (4 * LIMI)
HUGE = (4 * BMAX)
PIPM = []

NULL = b" "

class nets:
	def __init__(self, maxb):
		self.leng = 0
		self.size = 0
		self.maxb = (maxb - SUBS)
		self.hold = b""
		self.buff = b""

class heds:
	def __init__(self, size=0, xtra=0, indx=0, prot="", srcs="", sprt="", dsts="", dprt=""):
		(self.size, self.xtra) = (size, xtra)
		(self.indx, self.prot) = (indx, prot)
		(self.srcs, self.sprt) = (srcs, sprt)
		(self.dsts, self.dprt) = (dsts, dprt)
		(self.asrc, self.adst) = (None, None)
		(self.psrc, self.pdst) = (None, None)
	def dupe(self):
		clas = type(self)
		objc = clas(self.size, self.xtra, self.indx, self.prot, self.srcs, self.sprt, self.dsts, self.dprt)
		return objc
	def ipvf(self, astr):
		if (not astr):
			astr = "0.0.0.0"
		info = astr.split(".")
		return ((int(info[0]) << 24) | (int(info[1]) << 16) | (int(info[2]) <<  8) | (int(info[3]) <<  0))
	def port(self, pstr):
		if (not pstr):
			pstr = "0"
		return (int(pstr) & 0xffff)
	def rips(self, ipno):
		return ("%d.%d.%d.%d" % ((ipno >> 24) & 0xff, (ipno >> 16) & 0xff, (ipno >>  8) & 0xff, (ipno >>  0) & 0xff, ))
	def pack(self):
		if (not self.asrc):
			self.asrc = self.ipvf(self.srcs)
			self.psrc = self.port(self.sprt)
		if (not self.adst):
			self.adst = self.ipvf(self.dsts)
			self.pdst = self.port(self.dprt)
		return struct.pack("III3sIHIH", self.size, self.xtra, self.indx, self.prot.encode(), self.asrc, self.psrc, self.adst, self.pdst)
	def unpa(self, inpt):
		try:
			info = struct.unpack("III3sIHIH", inpt)
			clas = type(self)
			objc = clas(info[0], info[1], info[2], info[3].decode(), self.rips(info[4]), str(info[5]), self.rips(info[6]), str(info[7]))
			return objc
		except:
			clas = type(self)
			objc = clas()
			return objc

class cons:
	def __init__(self, stat=0, indx=0, sock=0, prot=0, leng=0, mlen=0, sigs=[0, 0], totl=[0, 0], sobj=None, buff=b"", last=0, logs=[0, 0, 0, 0], syns=None, addr=None, head=None):
		self.stat = stat
		(self.indx, self.sock, self.prot, self.leng, self.mlen) = (indx, sock, prot, leng, mlen)
		(self.sigs, self.totl) = (sigs, totl)
		self.sobj = sobj
		self.buff = buff
		(self.last, self.logs) = (last, logs)
		self.syns = syns
		self.addr = addr
		self.head = head
	def fins(self):
		if (self.sobj and (self.sobj.fileno() > 0)):
			try:
				self.sobj.shutdown(socket.SHUT_RDWR)
			except:
				pass
			try:
				self.sobj.close()
			except:
				pass
			self.sock = -1
	def zero(self):
		clas = type(self)
		objc = clas()
		self.head = heds()
		self.addr = objc.addr
		self.syns = objc.syns
		(self.last, self.logs) = (objc.last, objc.logs)
		self.buff = objc.buff
		self.sobj = objc.sobj
		(self.sigs, self.totl) = (objc.sigs, objc.totl)
		(self.indx, self.sock, self.prot, self.leng, self.mlen) = (objc.indx, objc.sock, objc.prot, objc.leng, objc.mlen)
		self.stat = objc.stat

class thrs:
	def __init__(self, indx=0, fsoc=0, sock=0, sobj=None, pipr=[], pipw=[], pipx=[], mode="", data=None, argp=None, conp=None, thrd=None, thrr=None, thrw=None):
		self.indx = indx
		self.fsoc = fsoc
		self.sock = sock
		self.sobj = sobj
		(self.pipr, self.pipw, self.pipx) = (pipr, pipw, pipx)
		self.mode = mode
		self.data = data
		self.argp = argp
		self.conp = conp
		(self.thrd, self.thrr, self.thrw) = (thrd, thrr, thrw)
	def dupe(self):
		clas = type(self)
		objc = clas(self.indx, self.fsoc, self.sock, self.sobj, self.pipr, self.pipw, self.pipx, self.mode, self.data, self.argp, self.conp, self.thrd, self.thrr, self.thrw)
		return objc

def numb(inpt, defv=0):
	try:
		return int(inpt)
	except:
		return defv

def uadr(inpt):
	try:
		info = inpt.split(":")
		return (info[0], int(info[1]))
	except:
		return None

def secs():
	return int(time.time())

def date():
	return time.strftime("%Y-%m-%d_%H:%M:%S")

def sels(socs, wait=None):
	try:
		return select.select(socs, [], [], wait)
	except:
		pass
	return ([], [], [None])

def senu(sock, buff, dest):
	try:
		sock.sendto(buff, dest)
		return True
	except Exception as e:
		print("ERRO", "senu", e)
	return False

def recu(sock, size):
	try:
		return sock.recvfrom(size)
	except Exception as e:
		print("ERRO", "recu", e)
	return (b"", None)

def rect(sock, size):
	try:
		return sock.recv(size)
	except Exception as e:
		print("ERRO", "rect", e)
	return b""

def stts(stas):
	if (((stas & STOP) == 0) and ((stas & TIMO) == 0)):
		if (((stas & JOIN) != 0) or ((stas & GOOD) != 0)):
			return 1
	return 0

def syns(sock, dest):
	try:
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		sock.settimeout(NSEC)
		sock.connect(dest)
		sock.settimeout(None)
		return True
	except Exception as e:
		pass
	return False

def synt(conp):
	if (syns(conp.sobj, conp.addr) != True):
		conp.stat |= STOP
	else:
		conp.stat |= GOOD
	print("%s SYNS [%s] [%d] [%d] [%d]" % (date(), "tcp", conp.sock, conp.stat & GOOD, conp.leng, ))
	conp.stat |= JOIN

def sall(sock, data):
	try:
		sock.sendall(data)
		return 1
	except Exception as e:
		print("ERRO", "sall", e)
	return -1

def rall(sock, mode, data):
	try:
		if (mode == 0):
			size = (data.maxb - data.leng)
			if (size < 1):
				return -1
			pntr = sock.recv(size)
			leng = len(pntr)
			if (leng < 1):
				return -2
			data.hold += pntr
			data.leng += leng
		if ((data.size < 1) and (data.leng >= OFFS)):
			data.size = struct.unpack("I", data.hold[:OFFS])[0]
			size = data.maxb
			if (data.size <= OFFS):
				return -3
			if (data.size >= size):
				return -4
		if ((data.size > 0) and (data.leng >= data.size)):
			size = data.size
			data.buff = data.hold[:size]
			left = (data.leng - size);
			data.hold = data.hold[size:]
			data.size = 0
			data.leng = left
			return size
	except Exception as e:
		print("ERRO", "rall", e)
		traceback.print_exc()
		return -9
	return 0

def comd(path, addr, prot):
	outp = b""
	try:
		cmdl = [path, addr[0], str(addr[1]), prot]
		subp = subprocess.check_output(cmdl, shell=False, text=True)
		outp = uadr(subp.strip())
	except:
		pass
	return outp

def coma(conp, addr, prot, path):
	dest = comd(path, addr, prot)
	if (not dest):
		return -1
	conp.head.prot = prot
	conp.head.srcs = addr[0]
	conp.head.sprt = str(addr[1])
	conp.head.dsts = dest[0]
	conp.head.dprt = str(dest[1])
	print("%s DEST [%s] [%s:%s]->[%s:%s]" % (date(), prot, conp.head.srcs, conp.head.sprt, conp.head.dsts, conp.head.dprt, ))
	return 1

def thrw(thrp):
	global STAT

	argp = thrp.argp
	conp = thrp.conp

	hedt = heds()
	hlen = len(hedt.pack())

	print("%s THRW [%d] [%c][%c] [%d]" % (date(), thrp.indx, argp.mode, thrp.mode, thrp.sock, ))

	os.write(thrp.pipw[1], NULL)

	while (1):
		if (STAT == INIT):
			time.sleep(1) ; continue
		if (STAT == HALT):
			break

		if ((thrp.sock < 1) or (thrp.pipr[0] < 1) or (thrp.pipx[0] < 1)):
			STAT = HALT ; print("HALT-0") ; break

		if (thrp.mode == "r"):
			lfds = [thrp.pipr[0]]
			for x in range(1, MAXC):
				if ((conp[x].indx == thrp.indx) and (stts(conp[x].stat) != 0)):
					if (conp[x].sock > 0):
						lfds.append(conp[x].sobj)

			(rfds, wfds, efds) = sels(lfds, SSEC)
			nows = secs()

			if (thrp.pipr[0] in rfds):
				os.read(thrp.pipr[0], 1)

			for indx in range(1, MAXC):
				if ((conp[indx].indx == thrp.indx) and (stts(conp[indx].stat) != 0)):
					buff = b""
					plen = 0 ; leng = 0
					if (conp[indx].leng > 0):
						if (conp[indx].prot == PUDP):
							plen = hlen
							buff = conp[indx].buff
							leng = len(buff)
							conp[indx].leng = 0
							os.write(thrp.pipw[1], NULL)
						if (conp[indx].prot == PTCP):
							plen = hlen
							leng = MAGL
							conp[indx].leng = 0
					if ((plen < 1) and (conp[indx].sock > 0) and (conp[indx].sobj in rfds)):
						if (conp[indx].prot == PUDP):
							plen = hlen
							(buff, addr) = recu(conp[indx].sobj, BUDP)
							leng = len(buff)
						if (conp[indx].prot == PTCP):
							plen = hlen
							buff = rect(conp[indx].sobj, BTCP)
							leng = len(buff)
					if (plen > 0):
						if (leng == MAGL):
							xtra = MAGL
							leng = 1
							print("%s MAKE [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, ))
						elif (leng > 0):
							xtra = 0
							conp[indx].totl[0] += leng
							if ((nows - conp[indx].logs[0]) >= OSEC):
								print("%s READ [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d][~%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, conp[indx].totl[0], ))
								conp[indx].logs[0] = nows
								conp[indx].totl[0] = 0
						else:
							xtra = MAGC
							leng = 1
							print("%s ENDS [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, ))
						while (len(buff) < leng):
							buff += b"!"
						plen += leng
						head = conp[indx].head.dupe()
						head.size = (plen & 0xffff)
						head.xtra = (xtra & 0xffff)
						info = head.pack()
						data = (info + buff)
						sall(thrp.sobj, data)
						conp[indx].last = nows
						if (xtra == MAGC):
							conp[indx].stat |= STOP
							os.write(PIPM[1], NULL)

		if (thrp.mode == "w"):
			lfds = [thrp.pipx[0], thrp.sobj]

			(rfds, wfds, efds) = sels(lfds, SSEC)
			nows = secs()

			if (thrp.pipx[0] in rfds):
				os.read(thrp.pipx[0], 1)
				for indx in range(1, MAXC):
					if ((conp[indx].indx == thrp.indx) and (stts(conp[indx].stat) != 0)):
						if (conp[indx].mlen > 0):
							print("%s XTCP [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d][x%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, conp[indx].mlen, conp[indx].totl[1], ))
							sall(conp[indx].sobj, conp[indx].buff)
							conp[indx].mlen = 0

			if (thrp.sobj in rfds):
				loop = 0
				while (loop > -1):
					erro = rall(thrp.sobj, loop, thrp.data)
					if (erro == 0):
						break
					if (erro < 0):
						STAT = HALT ; print("HALT-1 %d [%s][%s]" % (erro, thrp.data.buff, thrp.data.hold, )) ; break
					pntr = thrp.data.buff[:hlen]
					head = hedt.unpa(pntr)
					plen = head.size
					xtra = head.xtra
					indx = (head.indx >> 16)
					tidx = (head.indx & 0xffff)
					leng = (plen - hlen)
					buff = thrp.data.buff[hlen:]
					if ((leng > BTCP) or (indx > (MAXC - 1)) or (tidx > MAXT)):
						STAT = HALT ; print("HALT-2 %d %d %d %d %d [%s][%s]" % (erro, tidx, indx, xtra, leng, thrp.data.buff, thrp.data.hold, )) ; break
					elif (xtra == MAGC):
						if (stts(conp[indx].stat) != 0):
							print("%s STOP [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, ))
							conp[indx].stat |= STOP
							os.write(PIPM[1], NULL)
						elif ((conp[indx].stat & STOP) != 0):
							if ((nows - conp[indx].logs[3]) >= OSEC):
								print("%s WEND [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d][x%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, conp[indx].totl[1], ))
								conp[indx].logs[3] = nows
						elif (conp[indx].stat == MAKE):
							if (conp[indx].prot == PTCP):
								print("%s WTCP [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, ))
								conp[indx].stat |= STOP
								os.write(PIPM[1], NULL)
						else:
							STAT = HALT ; print("HALT-3 %d %d %d %d %d [%s][%s]" % (erro, tidx, indx, xtra, leng, thrp.data.buff, thrp.data.hold, )) ; break
					elif (leng > 0):
						if (conp[indx].stat == NOOP):
							if ((argp.mode == "s") and (thrp.mode == "w")):
								conp[indx].head = head.dupe()
								conp[indx].addr = (head.dsts, int(head.dprt))
								print("%s CONN [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, ))
								if (head.prot == "udp"):
									sobj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
									fdes = sobj.fileno()
									conp[indx].indx = tidx
									conp[indx].sobj = sobj
									conp[indx].sock = fdes
									conp[indx].last = nows
									conp[indx].prot = PUDP
									conp[indx].stat = GOOD
									conp[indx].sigs = [0, 0]
									conp[indx].syns = None
									senu(sobj, buff, conp[indx].addr)
									os.write(thrp.pipr[1], NULL)
									os.write(thrp.pipx[1], NULL)
									print("%s SYNS [%s] [%d] [%d] [%d]" % (date(), "udp", conp[indx].sock, conp[indx].stat & GOOD, leng, ))
								if (head.prot == "tcp"):
									sobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
									fdes = sobj.fileno()
									conp[indx].indx = tidx
									conp[indx].sobj = sobj
									conp[indx].sock = fdes
									conp[indx].last = nows
									conp[indx].prot = PTCP
									conp[indx].stat = MAKE
									conp[indx].sigs = [thrp.pipr[1], thrp.pipx[1]]
									conp[indx].syns = threading.Thread(target=synt, args=(conp[indx], ))
									conp[indx].syns.start()
							else:
								STAT = HALT ; print("HALT-4 %d %d %d %d %d [%s][%s]" % (erro, tidx, indx, xtra, leng, thrp.data.buff, thrp.data.hold, )) ; break
						elif ((tidx != thrp.indx) or (thrp.indx != conp[indx].indx)):
							STAT = HALT ; print("HALT-5 %d %d %d %d %d [%s][%s]" % (erro, tidx, indx, xtra, leng, thrp.data.buff, thrp.data.hold, )) ; break
						elif (conp[indx].stat == MAKE):
							if (conp[indx].prot == PTCP):
								print("%s STCP [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d][x%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, conp[indx].totl[1], ))
								conp[indx].buff = buff
								conp[indx].mlen = leng
								os.write(thrp.pipx[1], NULL)
						elif (stts(conp[indx].stat) != 0):
							sobj = conp[indx].sobj
							if (conp[indx].prot == PUDP):
								if ((argp.mode == "c") and (thrp.mode == "w")):
									sobj = argp.fudp
								senu(sobj, buff, conp[indx].addr)
							if (conp[indx].prot == PTCP):
								sall(sobj, buff)
							conp[indx].last = nows
							conp[indx].totl[1] += len(buff)
							if ((nows - conp[indx].logs[1]) >= OSEC):
								print("%s SEND [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d][~%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, conp[indx].totl[1], ))
								conp[indx].logs[1] = nows
								conp[indx].totl[1] = 0
						elif ((conp[indx].stat & STOP) != 0):
							if ((nows - conp[indx].logs[2]) >= OSEC):
								print("%s WLEN [%d][%d] [%c][%c] [%s] [%s:%s] -> [%s:%s] [%d][%d][x%d]" % (date(), thrp.indx, indx, argp.mode[0], thrp.mode[0], conp[indx].head.prot, conp[indx].head.srcs, conp[indx].head.sprt, conp[indx].head.dsts, conp[indx].head.dprt, conp[indx].sock, leng, conp[indx].totl[1], ))
								conp[indx].logs[2] = nows;
						else:
							STAT = HALT ; print("HALT-6 %d %d %d %d %d [%s][%s]" % (erro, tidx, indx, xtra, leng, thrp.data.buff, thrp.data.hold, )) ; break
					else:
						STAT = HALT ; print("HALT-7 %d %d %d %d %d [%s][%s]" % (erro, tidx, indx, xtra, leng, thrp.data.buff, thrp.data.hold, )) ; break
					loop = 1

def thrd(thrp):
	global STAT
	global SEQS

	argp = thrp.argp

	if (argp.mode == "c"):
		while (thrp.indx != SEQS):
			time.sleep(1)
		thrp.sobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		thrp.sock = thrp.sobj.fileno()
		while (1):
			if (syns(thrp.sobj, argp.remo) == True):
				break
			print("%s WARN [%s] [%d][%d]" % (date(), argp.remo, thrp.indx, thrp.sock, ))
			time.sleep(1)
		print("%s CLIE [%s] [%d][%d]" % (date(), argp.remo, thrp.indx, thrp.sock, ))
		SEQS += 1

	if (argp.mode == "s"):
		while (thrp.sock < 1):
			time.sleep(1)
		print("%s SERV [%s] [%d][%d]" % (date(), argp.locl, thrp.indx, thrp.sock, ))
		SEQS += 1

	thor = thrp.dupe()
	thor.mode = "r"
	thor.thrr = threading.Thread(target=thrw, args=(thor, ))
	thor.thrr.start()

	thow = thrp.dupe()
	thow.mode = "w"
	thow.thrw = threading.Thread(target=thrw, args=(thow, ))
	thow.thrw.start()

	if ((thrp.indx == MAXT) and (STAT == INIT)):
		STAT = PROC

	thor.thrr.join()
	thow.thrw.join()

def mgmt(thrp):
	argp = thrp.argp
	conp = thrp.conp

	redo = CDEL if (argp.mode == "c") else SDEL

	while (1):
		if (STAT == INIT):
			time.sleep(1) ; continue
		if (STAT == HALT):
			break

		lfds = [PIPM[0]]
		(rfds, wfds, efds) = sels(lfds, 1)
		nows = secs()

		if (PIPM[0] in rfds):
			os.read(PIPM[0], 1)

		for x in range(1, MAXC):
			indx = conp[x].indx
			sock = conp[x].sock
			last = conp[x].last
			if (stts(conp[x].stat) != 0):
				if ((conp[x].prot == PUDP) and ((nows - last) > argp.eudp)):
					conp[x].stat |= STOP
					print("%s EXPR [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), indx, x, conp[x].head.prot, conp[x].head.srcs, conp[x].head.sprt, conp[x].head.dsts, conp[x].head.dprt, sock, redo, ))
				if ((conp[x].prot == PTCP) and ((nows - last) > argp.etcp)):
					conp[x].stat |= STOP
					print("%s EXPR [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), indx, x, conp[x].head.prot, conp[x].head.srcs, conp[x].head.sprt, conp[x].head.dsts, conp[x].head.dprt, sock, redo, ))
			if ((conp[x].stat & JOIN) != 0):
				if (conp[x].syns):
					conp[x].syns.join()
					conp[x].stat &= (~JOIN)
					print("%s JOIN [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), indx, x, conp[x].head.prot, conp[x].head.srcs, conp[x].head.sprt, conp[x].head.dsts, conp[x].head.dprt, sock, redo, ))
			if ((conp[x].stat & TIMO) != 0):
				if ((nows - last) >= redo):
					print("%s ZERO [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), indx, x, conp[x].head.prot, conp[x].head.srcs, conp[x].head.sprt, conp[x].head.dsts, conp[x].head.dprt, sock, redo, ))
					conp[x].zero()
			if ((conp[x].stat & STOP) != 0):
				if ((conp[x].stat & TIMO) == 0):
					print("%s FINS [%d][%d] [m][m] [%s] [%s:%s] -> [%s:%s] [%d][%d]" % (date(), indx, x, conp[x].head.prot, conp[x].head.srcs, conp[x].head.sprt, conp[x].head.dsts, conp[x].head.dprt, sock, redo, ))
					conp[x].fins()
					conp[x].stat |= TIMO
					conp[x].last = nows

def serv(argp):
	global STAT
	global PIPM

	argp.fudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	argp.fudp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	argp.fudp.bind(argp.locl)

	argp.ftcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	argp.ftcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	argp.ftcp.bind(argp.locl)
	argp.ftcp.listen(QUES)

	conp = []
	for x in range(0, MAXC):
		cono = cons()
		hedo = heds()
		cono.head = hedo
		conp.append(cono)
	PIPM = os.pipe()

	thrp = []
	for x in range(0, MAXT):
		thro = thrs()
		thro.indx = (x + 1) ; thro.argp = argp ; thro.conp = conp
		thro.pipr = os.pipe() ; thro.pipw = os.pipe() ; thro.pipx = os.pipe()
		thro.data = nets(HUGE)
		thro.thrd = threading.Thread(target=thrd, args=(thro, ))
		thro.thrd.start()
		thrp.append(thro)

	thrm = threading.Thread(target=mgmt, args=(thrp[0], ))
	thrm.start()

	tidx = 0
	while (1):
		if (STAT == HALT):
			break

		(rfds, wfds, efds) = sels([argp.fudp, argp.ftcp], SSEC)
		nows = secs()

		if (argp.fudp in rfds):
			(data, addr) = recu(argp.fudp, BUDP)
			if (data):
				if (argp.mode == "c"):
					indx = -1 ; fidx = -1
					for x in range(1, MAXC):
						if ((stts(conp[x].stat) != 0) and (conp[x].addr == addr)):
							indx = x
						if ((conp[x].stat == NOOP) and (fidx < 0)):
							fidx = x
					if ((indx < 1) and (fidx > 0)):
						if (coma(conp[fidx], addr, "udp", argp.comd) > 0):
							zidx = (tidx + 1)
							conp[fidx].addr = addr
							conp[fidx].head.indx = (((fidx & 0xffff) << 16) | (zidx & 0xffff))
							conp[fidx].indx = zidx
							conp[fidx].last = nows
							conp[fidx].sobj = None
							conp[fidx].sock = NOOP
							conp[fidx].prot = PUDP
							conp[fidx].stat = GOOD
							conp[fidx].leng = NOOP
							indx = fidx
							tidx = ((tidx + 1) % MAXT)
					if (indx > 0):
						zidx = conp[indx].indx
						os.read(thrp[zidx - 1].pipw[0], 1)
						conp[indx].buff = data
						conp[indx].leng = len(data)
						os.write(thrp[zidx - 1].pipr[1], NULL)

				if (argp.mode == "s"):
					pass

		if (argp.ftcp in rfds):
			(conn, addr) = argp.ftcp.accept()
			if (conn):
				if (argp.mode == "c"):
					fidx = -1 ; fdes = conn.fileno()
					for x in range(1, MAXC):
						if (conp[x].stat == NOOP):
							fidx = x ; break
					if (fidx > 0):
						if (coma(conp[fidx], addr, "tcp", argp.comd) > 0):
							zidx = (tidx + 1)
							conp[fidx].addr = addr
							conp[fidx].head.indx = (((fidx & 0xffff) << 16) | (zidx & 0xffff))
							conp[fidx].indx = zidx
							conp[fidx].last = nows
							conp[fidx].sobj = conn
							conp[fidx].sock = fdes
							conp[fidx].prot = PTCP
							conp[fidx].stat = GOOD
							conp[fidx].leng = MAGL
							os.write(thrp[zidx - 1].pipr[1], NULL)
							tidx = ((tidx + 1) % MAXT)
						else:
							conn.close()

				if (argp.mode == "s"):
					if (tidx < MAXT):
						fdes = conn.fileno()
						thrp[tidx].sock = fdes
						thrp[tidx].sobj = conn
						print("%s ACCP [%d][%d]" % (date(), tidx + 1, fdes, ))
						tidx += 1

def main(argv):
	global MAXT
	global MAXC
	global HUGE

	argp = argparse.ArgumentParser(description="mitm")
	argp.add_argument("-c", "--comd", action="store", default=" ")
	argp.add_argument("-m", "--mode", action="store", default=" ")
	argp.add_argument("-l", "--locl", action="store", default=" ")
	argp.add_argument("-r", "--remo", action="store", default=" ")
	argp.add_argument("-k", "--skey", action="store", default=" ")
	argp.add_argument("-u", "--eudp", action="store", default=" ")
	argp.add_argument("-t", "--etcp", action="store", default=" ")
	argp.add_argument("-z", "--work", action="store", default=" ")

	args = argp.parse_args(argv)

	args.locl = uadr(args.locl)
	args.remo = uadr(args.remo)
	args.eudp = numb(args.eudp, 35)
	args.etcp = numb(args.etcp, 95000)
	args.work = numb(args.work, 4)

	MAXT = args.work
	MAXC = (MAXT * LIMI)
	# HUGE = (MAXT * BMAX)

	skey = os.environ.get("SKEY", None)
	if (skey):
		args.skey = skey

	#sigs()
	#srnd()

	print("%s INIT %s %s %s" % (date(), args.mode, args.eudp, args.etcp, ))
	serv(args)

if (__name__ == "__main__"):
	main(sys.argv[1:])
