from amitools.vamos.libcore.impl import LibImpl

import errno
import select
import socket as s
from amitools.vamos.astructs.astructdef import AmigaStructDef, AmigaClassDef
from amitools.vamos.astructs.astruct import AmigaStruct
from amitools.vamos.astructs.string import CSTR
from amitools.vamos.astructs.pointer import APTR_VOID
from amitools.vamos.astructs.scalar import LONG, UBYTE, UWORD, ULONG
from amitools.vamos.libtypes import TagList, TagItem
from amitools.vamos.log import log_bsdsocket


class BsdSocketLibrary(LibImpl):

    # Map from native Python socket constants to bsdsocket constants
    _AF = {
        s.AF_INET: 2,
    }
    _PROTO = {
        s.IPPROTO_TCP: 6,
        s.IPPROTO_UDP: 17,
    }
    _STYPE = {
        s.SOCK_STREAM: 1,
        s.SOCK_DGRAM: 2,
    }
    _LEVEL = {
        s.SOL_SOCKET: 0xFFFF,
    }

    # Map from native Python errno constants to Amiga errno constants
    _ERRORS = {
        errno.EACCES: 13,
        errno.EAFNOSUPPORT: 47,
        errno.EAGAIN: 35,
        errno.EBADF: 9,
        errno.EINPROGRESS: 36,
        errno.EINVAL: 22,
        errno.EMFILE: 24,
        errno.ENFILE: 23,
        errno.ENOBUFS: 55,
        errno.ENOMEM: 12,
        errno.EPROTONOSUPPORT: 43,
        errno.EWOULDBLOCK: 35,
    }

    # ioctls
    _FIONBIO = 0x667E

    def setup_lib(self, ctx, base_addr):
        self.alloc = ctx.alloc
        self.cnt = 0
        # track opened sockets
        self.socks = {}
        # get host by name
        self.hostByName = None
        # error handling
        self.errno = 0
        self.errnoaddr = None

    def finish_lib(self, ctx):
        self.cnt = None

    def open_lib(self, ctx, open_cnt):
        self.cnt = open_cnt

    def close_lib(self, ctx, open_cnt):
        if self.hostByName != None:
            self.hostByName.free()
            self.hostByName = None
        self.cnt = open_cnt

    def get_version(self):
        return 4

    def get_cnt(self):
        return self.cnt

    def putSock(self, sock):
        n = 3  # Skip over std{in,out,err}
        while True:
            if not n in self.socks:
                self.socks[n] = sock
                return n
            n = n + 1

    def _set_errno(self, ctx, error):
        log_bsdsocket.info("err: %d", error)
        self.errno = self._ERRORS[error]
        if self.errnoaddr is not None:
            ctx.mem.w32(self.errnoaddr, self.errno)

    def socket(self, ctx, domain, typ, protocol):
        if domain not in (self._AF[s.AF_INET],):
            log_bsdsocket.info("socket(): unsupported domain %d", domain)
            self._set_errno(ctx, errno.EAFNOSUPPORT)
            return -1

        if typ == self._STYPE[s.SOCK_STREAM]:
            ptyp = s.SOCK_STREAM
            protos = (0, self._PROTO[s.IPPROTO_TCP])
        elif typ == self._STYPE[s.SOCK_DGRAM]:
            ptyp = s.SOCK_DGRAM
            protos = (0, self._PROTO[s.IPPROTO_UDP])
        else:
            ptyp = s.SOCK_RAW
            protos = (self._PROTO[s.IPPROTO_TCP], self._PROTO[s.IPPROTO_UDP])

        if protocol not in protos:
            log_bsdsocket.info("socket(): unsupported protocol %d", protocol)
            self._set_errno(ctx, errno.EPROTONOSUPPORT)
            return -1

        proto = protocol
        if proto != 0:
            proto = {v: k for k, v in self._PROTO.items()}[proto]

        try:
            sock = s.socket(s.AF_INET, ptyp, proto)
        except OSError as err:
            log_bsdsocket.info("socket(): create failed: %d", err.errno)
            self._set_errno(ctx, err.errno)
            return -1
        if sock is None:
            log_bsdsocket.info("socket(): create returned None")
            self._set_errno(ctx, errno.EINVAL)
            return -1

        sockn = self.putSock(sock)
        log_bsdsocket.info("socket(%d, %d, %d) = %d", domain, typ, protocol, sockn)
        return sockn

    def CloseSocket(self, ctx, sockn):
        log_bsdsocket.info("CloseSocket(%d)", sockn)
        if sockn in self.socks:
            sock = self.socks[sockn]
            sock.close()
            del self.socks[sockn]
            return 0
        log_bsdsocket.info("CloseSocket(): badfd: %d", sockn)
        self._set_errno(ctx, errno.EBADF)
        return -1

    def gethostbyname(self, ctx, pname):
        name = ctx.mem.r_cstr(pname)
        h = s.gethostbyname(name)
        if h != None:
            ip = self.s2ip(h)
            log_bsdsocket.info("gethostbyname(%s) = %s", name, h)

            if self.hostByName == None:
                self.hostByName = HostEntClass.alloc(self.alloc)

            self.hostByName.h_name.set(pname)
            self.hostByName.h_aliases.set(self.hostByName._addr + 20)
            self.hostByName.h_addrtype.set(self._AF[s.AF_INET])
            self.hostByName.h_length.set(1)
            self.hostByName.h_addr_list.set(self.hostByName._addr + 24)
            self.hostByName.alias_term.set(0)
            self.hostByName.addr.set(self.hostByName._addr + 32)
            self.hostByName.addr_term.set(0)
            self.hostByName.addr_val.set(ip)
            return self.hostByName._addr

        return 0

    def bind(self, ctx, sockn, addr, addrlen):
        if not sockn in self.socks:
            log_bsdsocket.info("bind(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        if addrlen < 8:
            log_bsdsocket.info("bind(): addrlen %d too small", addrlen)
            self._set_errno(ctx, errno.EINVAL)
            return -1

        soa = SockAddrClass(ctx.mem, addr)
        ip = soa.sin_addr.get()
        ip_s = self.ip2s(ip)

        log_bsdsocket.info("bind(%d, %s, %d)", sockn, ip_s, soa.sin_port.get())
        sock.bind((ip_s, soa.sin_port.get()))
        return 0

    def connect(self, ctx, sockn, name, namelen):
        if not sockn in self.socks:
            log_bsdsocket.info("connect(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        if namelen < 8:
            log_bsdsocket.info("connect(): namelen too small: %d", namelen)
            self._set_errno(ctx, errno.EINVAL)
            return -1

        soa = SockAddrClass(ctx.mem, name)

        if soa.sin_port.get() == 0:
            # port is necessary
            log_bsdsocket.info("connect(): port needed")
            self._set_errno(ctx, errno.EINVAL)
            return -1

        ip = soa.sin_addr.get()
        ip_s = self.ip2s(ip)
        log_bsdsocket.info('connect(%d, "%s:%d")', sockn, ip_s, soa.sin_port.get())
        try:
            sock.connect((ip_s, soa.sin_port.get()))
        except BlockingIOError:
            assert not sock.getblocking()
            log_bsdsocket.info("connect(%d): would block", sockn)
            self._set_errno(ctx, errno.EINPROGRESS)
            return -1
        except OSError as err:
            log_bsdsocket.info("connect(): failed: %d", err.errno)
            self._set_errno(ctx, err.errno)
            return -1
        return 0

    def SocketBaseTagList(self, ctx, tag_list: TagList):
        log_bsdsocket.info("SocketBaseTagList(%s)", tag_list)
        m_user = 1 << 31
        m_ref = 1 << 15
        m_set = 1 << 0
        m_code = 0x3FFF << 1
        for idx, tag_item in enumerate(tag_list):
            tag, data = tag_item.get_tuple(do_map=False)
            if not (tag & m_user):
                continue
            code = (tag & m_code) >> 1
            ref_or_val = {True: "byref", False: "byval"}[bool(tag & m_ref)]
            set_or_get = {True: "set", False: "get"}[bool(tag & m_set)]
            if code == 24 and set_or_get == "set":
                # SBTC_ERRNOLONGPTR
                if ref_or_val == "byval":
                    self.errnoaddr = data
        return 0

    def getsockopt(self, ctx, sockn, level, optname, optval, optlen):
        if not sockn in self.socks:
            log_bsdsocket.info("getsockopt(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        if level not in (self._LEVEL[s.SOL_SOCKET], self._PROTO[s.IPPROTO_TCP]):
            log_bsdsocket.info("getsockopt(): unknown level: %d", level)
            self._set_errno(ctx, errno.EINVAL)
            return -1

        buflen = ctx.mem.r32(optlen)

        log_bsdsocket.info(
            "getsockopt(%d, %x, %x, %x, %d)",
            sockn,
            level,
            optname,
            optval,
            buflen,
        )

        name = (
            {
                6: {  # IPPROTO_TCP
                    0x0001: "TCP_NODELAY",
                    0x0002: "TCP_MAXSEG",
                },
                0xFFFF: {  # SOL_SOCKET
                    0x0001: "SO_DEBUG",
                    0x0002: "SO_ACCEPTCONN",
                    0x0004: "SO_REUSEADDR",
                    0x0008: "SO_KEEPALIVE",
                    0x0010: "SO_DONTROUTE",
                    0x0020: "SO_BROADCAST",
                    0x0040: "SO_USELOOPBACK",
                    0x0080: "SO_LINGER",
                    0x0100: "SO_OOBINLINE",
                    0x0200: "SO_REUSEPORT",
                    0x1001: "SO_SNDBUF",
                    0x1002: "SO_RCVBUF",
                    0x1003: "SO_SNDLOWAT",
                    0x1004: "SO_RCVLOWAT",
                    0x1005: "SO_SNDTIMEO",
                    0x1006: "SO_RECVTIMEO",
                    0x1007: "SO_ERROR",
                    0x1008: "SO_TYPE",
                    0x2001: "SO_EVENTMASK",
                },
            }
            .get(level, {})
            .get(optname, None)
        )

        if name == "SO_ERROR":
            if buflen < 4:
                log_bsdsocket.info("getsockopt(): buflen %d too small", buflen)
                self._set_errno(ctx, errno.EINVAL)
                return -1
            error = sock.getsockopt(s.SOL_SOCKET, s.SO_ERROR)
            if error != 0:
                error = self._ERRORS[error]
            ctx.mem.w32(optval, error)
            buflen = 4
        else:
            log_bsdsocket.info("getsockopt(): unsupported option %s", name)
            self._set_errno(ctx, errno.ENOPROTOOPT)
            return -1
        ctx.mem.w32(optlen, buflen)
        return 0

    def setsockopt(self, ctx, sockn, level, optname, optval, optlen):
        if not sockn in self.socks:
            log_bsdsocket.info("setsockopt(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        if level not in (self._LEVEL[s.SOL_SOCKET], self._PROTO[s.IPPROTO_TCP]):
            log_bsdsocket.info("setsockopt(): unknown level: %d", level)
            self._set_errno(ctx, errno.EINVAL)
            return -1

        log_bsdsocket.debug(
            "setsockopt(%d, %x, %x, %x, %d)",
            sockn,
            level,
            optname,
            optval,
            optlen,
        )

        name = (
            {
                6: {  # IPPROTO_TCP
                    0x0001: "TCP_NODELAY",
                    0x0002: "TCP_MAXSEG",
                },
                0xFFFF: {  # SOL_SOCKET
                    0x0001: "SO_DEBUG",
                    0x0002: "SO_ACCEPTCONN",
                    0x0004: "SO_REUSEADDR",
                    0x0008: "SO_KEEPALIVE",
                    0x0010: "SO_DONTROUTE",
                    0x0020: "SO_BROADCAST",
                    0x0040: "SO_USELOOPBACK",
                    0x0080: "SO_LINGER",
                    0x0100: "SO_OOBINLINE",
                    0x0200: "SO_REUSEPORT",
                    0x1001: "SO_SNDBUF",
                    0x1002: "SO_RCVBUF",
                    0x1003: "SO_SNDLOWAT",
                    0x1004: "SO_RCVLOWAT",
                    0x1005: "SO_SNDTIMEO",
                    0x1006: "SO_RECVTIMEO",
                    0x1007: "SO_ERROR",
                    0x1008: "SO_TYPE",
                    0x2001: "SO_EVENTMASK",
                },
            }
            .get(level, {})
            .get(optname, None)
        )

        if name == "SO_REUSEADDR":
            if optlen != 4:
                log_bsdsocket.info("setsockopt(): invalid optlen %d", optlen)
                self._set_errno(ctx, errno.EINVAL)
                return -1
            val = 1 if ctx.mem.r32(optval) else 0
            log_bsdsocket.info("setsockopt(SOL_SOCKET, SO_REUSEADDR, %d)", val)
            sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, val)
        elif name == "TCP_NODELAY":
            if optlen != 4:
                log_bsdsocket.info("setsockopt(): invalid optlen %d", optlen)
                self._set_errno(ctx, errno.EINVAL)
                return -1
            val = 1 if ctx.mem.r32(optval) else 0
            log_bsdsocket.info("setsockopt(IPPROTO_TCP, TCP_NODELAY, %d)", val)
            sock.setsockopt(s.IPPROTO_TCP, s.TCP_NODELAY, val)
        else:
            log_bsdsocket.info("getsockopt(): unsupported option %s", name)
            self._set_errno(ctx, errno.ENOPROTOOPT)
            return -1
        return 0

    def getsockname(self, ctx, sockn, name, namelen):
        if not sockn in self.socks:
            log_bsdsocket.info("getsockname(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        addrinfo = sock.getsockname()

        addrlen = ctx.mem.r32(namelen)
        if addrlen != SockAddrClass.get_size():
            log_bsdsocket.info("getsockname(): unacceptable namelen: %d", addrlen)
            self._set_errno(ctx, errno.EINVAL)
            return -1

        log_bsdsocket.info(
            "getsockname(%d, %x, %d) = %s:%d",
            sockn,
            name,
            addrlen,
            addrinfo[0],
            addrinfo[1],
        )

        soa = SockAddrClass(ctx.mem, name)

        soa.sin_len.set(addrlen)
        soa.sin_family.set(self._AF[s.AF_INET])
        soa.sin_port.set(addrinfo[1])
        soa.sin_addr.set(self.s2ip(addrinfo[0]))
        soa.sin_zero0.set(0)
        soa.sin_zero1.set(0)

        return 0

    def listen(self, ctx, sockn, backlog):
        if not sockn in self.socks:
            log_bsdsocket.info("listen(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        log_bsdsocket.info("listen(%d, %d)", sockn, backlog)
        sock.listen(backlog)
        return 0

    def IoctlSocket(self, ctx, sockn, request, argp):
        if not sockn in self.socks:
            log_bsdsocket.info("IoctlSocket(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        m_dir = 0xE0000000
        m_plen = 0x1FFF0000
        m_cmd = 0xFFFF

        inout = {
            0x20000000: "void",
            0x40000000: "out",
            0x80000000: "in",
            0xC0000000: "inout",
        }[request & m_dir]
        plen = (request & m_plen) >> 16
        cmd = request & m_cmd

        log_bsdsocket.debug(
            "IoctlSocket(%d, %x, %x): cmd=%x arglen=%d dir=%s",
            sockn,
            request,
            argp,
            cmd,
            plen,
            inout,
        )

        if cmd == self._FIONBIO:
            if plen != 4:
                log_bsdsocket.info("IoctlSocket(): invalid arglen")
                self._set_errno(ctx, errno.EINVAL)
                return -1
            arg = True if ctx.mem.r32(argp) else False
            log_bsdsocket.info("IoctlSocket(%d, FIONBIO, %d)", sockn, arg)
            sock.setblocking(not arg)
        else:
            log_bsdsocket.info("IoctlSocket(): unknown cmd")
            self._set_errno(ctx, errno.EINVAL)
            return -1

        return 0

    def accept(self, ctx, sockn, addr, addrlen):
        if not sockn in self.socks:
            log_bsdsocket.info("accept(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        if addr != 0:
            alen = ctx.mem.r32(addrlen)
            if alen < SockAddrClass.get_size():
                log_bsdsocket.info("accept(): unacceptable namelen %d", alen)
                self._set_errno(ctx, errno.EINVAL)
                return -1

        log_bsdsocket.debug("accept(%d, %x, %x)", sockn, addr, addrlen)
        try:
            csock, addrinfo = sock.accept()
        except BlockingIOError:
            assert not sock.getblocking()
            self._set_errno(ctx, errno.EWOULDBLOCK)
            return -1
        except OSError as err:
            log_bsdsocket.info("accept(): failed: %d", err.errno)
            self._set_errno(ctx, err.errno)
            return -1

        csockn = self.putSock(csock)

        log_bsdsocket.info(
            "accept(%d, %x, %x) = %d (%s:%d)",
            sockn,
            addr,
            addrlen,
            csockn,
            addrinfo[0],
            addrinfo[1],
        )

        if addr != 0:
            soa = SockAddrClass(ctx.mem, name)
            soa.sin_len.set(addrlen)
            soa.sin_family.set(self._AF[s.AF_INET])
            soa.sin_port.set(addrinfo[1])
            soa.sin_addr.set(self.s2ip(addrinfo[0]))
            soa.sin_zero0.set(0)
            soa.sin_zero1.set(0)

            ctx.mem.w32(addrlen, soa.get_size())

        return csockn

    def ip2s(self, ip):
        return (
            str((ip >> 24) & 0xFF)
            + "."
            + str((ip >> 16) & 0xFF)
            + "."
            + str((ip >> 8) & 0xFF)
            + "."
            + str(ip & 0xFF)
        )

    def s2ip(self, s):
        vals = [int(v) for v in s.split(".")]
        return (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]

    def send(self, ctx, sockn, buf, blen, flags):
        if not sockn in self.socks:
            log_bsdsocket.info("send(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1

        log_bsdsocket.debug("send(%d, %x, %d, %x)", sockn, buf, blen, flags)

        data = ctx.mem.r_block(buf, blen)

        sock = self.socks[sockn]
        try:
            return sock.send(data, flags)
        except BlockingIOError:
            assert not sock.getblocking()
            self._set_errno(ctx, errno.EWOULDBLOCK)
            return -1
        except OSError as err:
            log_bsdsocket.info("send(): failed: %d", err.errno)
            self._set_errno(ctx, err.errno)
            return -1

        return blen

    def recv(self, ctx, sockn, buf, blen, flags):
        if not sockn in self.socks:
            log_bsdsocket.info("recv(): unknown sockfd: %d", sockn)
            self._set_errno(ctx, errno.EBADF)
            return -1
        sock = self.socks[sockn]

        log_bsdsocket.debug("recv(%d, %x, %d, %x)", sockn, buf, blen, flags)

        try:
            read = sock.recv(blen, flags)
        except BlockingIOError:
            assert not sock.getblocking()
            self._set_errno(ctx, errno.EWOULDBLOCK)
            return -1
        except OSError as err:
            log_bsdsocket.info("recv(): failed: %d", err.errno)
            self._set_errno(ctx, err.errno)
            return -1

        sz = len(read)
        ctx.mem.w_block(buf, read)
        return sz

    def listFromFdSet(self, mem, addr, sz):
        fdset = ULongULongClass(mem, addr)
        l = fdset.l0.get() + (fdset.l1.get() << 32)
        r = []
        for i in range(0, sz):
            if l & (1 << i) != 0:
                if i in self.socks:
                    r.append(self.socks[i])
                elif 0 <= i <= 2:
                    # std{in,out,err}
                    r.append(i)
        return r

    def markFdSet(self, mem, lst, addr, sz):
        nset = 0
        if addr != 0:
            s = set(lst)
            fdset = ULongULongClass(mem, addr)
            l = 0
            for i in range(0, sz):
                if 0 <= i <= 2 and i in s:
                    # std{in,out,err}
                    l = l | (1 << i)
                    nset += 1
                elif i in self.socks and self.socks[i] in s:
                    l = l | (1 << i)
                    nset += 1
            fdset.l0.set(l)
            fdset.l1.set(l >> 32)
        return nset

    def WaitSelect(self, ctx, nfds, read_fds, write_fds, except_fds, timeout, signals):
        # clear signals
        if signals != 0:
            sig = ULongULongStruct(ctx.mem, signals)
            sig.l0.set(0)

        rlist, wlist, xlist = [], [], []
        if read_fds != 0:
            rlist = self.listFromFdSet(ctx.mem, read_fds, nfds)
        if write_fds != 0:
            wlist = self.listFromFdSet(ctx.mem, write_fds, nfds)
        if except_fds != 0:
            xlist = self.listFromFdSet(ctx.mem, except_fds, nfds)

        r, w, x, tmout = None, None, None, None
        if timeout != 0:
            timeval = ULongULongClass(ctx.mem, timeout)
            tmout = timeval.l0.get() + timeval.l1.get() * 1e-6

        log_bsdsocket.debug(
            "WaitSelect(%d, %s, %s, %s, %f, %d)",
            nfds,
            rlist,
            wlist,
            xlist,
            tmout,
            signals,
        )

        r, w, x = select.select(rlist, wlist, xlist, tmout)

        res = 0
        res += self.markFdSet(ctx.mem, r, read_fds, nfds)
        res += self.markFdSet(ctx.mem, w, write_fds, nfds)
        res += self.markFdSet(ctx.mem, x, except_fds, nfds)

        log_bsdsocket.debug(
            "WaitSelect(%d, %s, %s, %s, %f, %d) => %d %s %s %s",
            nfds,
            rlist,
            wlist,
            xlist,
            tmout,
            signals,
            res,
            r,
            w,
            x,
        )

        return res


@AmigaStructDef
class ULongULongStruct(AmigaStruct):
    _format = [
        (ULONG, "l0"),
        (ULONG, "l1"),
    ]


@AmigaClassDef
class ULongULongClass(ULongULongStruct):
    pass


@AmigaStructDef
class SockAddrStruct(AmigaStruct):
    _format = [
        (UBYTE, "sin_len"),
        (UBYTE, "sin_family"),
        (UWORD, "sin_port"),
        (ULONG, "sin_addr"),
        (ULONG, "sin_zero0"),
        (ULONG, "sin_zero1"),
    ]


@AmigaClassDef
class SockAddrClass(SockAddrStruct):
    pass


@AmigaStructDef
class HostEntStruct(AmigaStruct):
    _format = [
        (CSTR, "h_name"),
        (APTR_VOID, "h_aliases"),
        (LONG, "h_addrtype"),
        (LONG, "h_length"),
        (APTR_VOID, "h_addr_list"),
        # internal
        (LONG, "alias_term"),
        (LONG, "addr"),
        (LONG, "addr_term"),
        (LONG, "addr_val"),
    ]


@AmigaClassDef
class HostEntClass(HostEntStruct):
    pass
