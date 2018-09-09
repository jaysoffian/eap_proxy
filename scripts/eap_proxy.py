#!/usr/bin/env python
"""
Inspired by 1x_prox as posted here:

    http://www.dslreports.com/forum/r30693618-

    AT&T Residential Gateway Bypass - True bridge mode!

usage: eap_proxy [-h] [--ping-gateway] [--ignore-when-wan-up] [--ignore-start]
                 [--ignore-logoff] [--restart-dhcp] [--set-mac] [--daemon]
                 [--pidfile PIDFILE] [--syslog] [--promiscuous] [--debug]
                 [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface of the AT&T ONT/WAN
  IF_ROUTER             interface of the AT&T router

optional arguments:
  -h, --help            show this help message and exit

checking whether WAN is up:
  --ping-gateway        normally the WAN is considered up if IF_WAN.0 has an
                        IP address; this option additionally requires that
                        there is a default route gateway that responds to a
                        ping

ignoring router packets:
  --ignore-when-wan-up  ignore router packets when WAN is up (see --ping-
                        gateway)
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

configuring IF_WAN.0 VLAN:
  --restart-dhcp        check whether WAN is up after receiving EAP-Success on
                        IF_WAN (see --ping-gateway); if not, restart dhclient
                        on IF_WAN.0
  --set-mac             set IF_WAN.0's MAC (ether) address to router's MAC
                        address

daemonization:
  --daemon              become a daemon; implies --syslog
  --pidfile PIDFILE     record pid to PIDFILE
  --syslog              log to syslog instead of stderr

debugging:
  --promiscuous         place interfaces into promiscuous mode instead of
                        multicast
  --debug               enable debug-level logging
  --debug-packets       print packets in hex format to assist with debugging;
                        implies --debug
"""
# pylint:disable=invalid-name,missing-docstring
import argparse
import array
import atexit
import ctypes
import ctypes.util
import logging
import logging.handlers
import os
import random
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback
from collections import namedtuple
from fcntl import ioctl
from functools import partial

### Constants

EAP_MULTICAST_ADDR = (0x01, 0x80, 0xc2, 0x00, 0x00, 0x03)
ETH_P_PAE = 0x888e  # IEEE 802.1X (Port Access Entity)
IFF_PROMISC = 0x100
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
SIOCGIFADDR = 0x8915
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SOL_PACKET = 263

### Sockets / Network Interfaces

class struct_packet_mreq(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("mr_ifindex", ctypes.c_int),
        ("mr_type", ctypes.c_ushort),
        ("mr_alen", ctypes.c_ushort),
        ("mr_address", ctypes.c_ubyte * 8))


if_nametoindex = ctypes.CDLL(ctypes.util.find_library('c')).if_nametoindex


def addsockaddr(sock, address):
    """Configure physical-layer multicasting or promiscuous mode for `sock`.
       If `addr` is None, promiscuous mode is configured. Otherwise `addr`
       should be a tuple of up to 8 bytes to configure that multicast address.
    """
    # pylint:disable=attribute-defined-outside-init
    mreq = struct_packet_mreq()
    mreq.mr_ifindex = if_nametoindex(getifname(sock))
    if address is None:
        mreq.mr_type = PACKET_MR_PROMISC
    else:
        mreq.mr_type = PACKET_MR_MULTICAST
        mreq.mr_alen = len(address)
        mreq.mr_address = address
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)


def rawsocket(ifname, poll=None, promisc=False):
    """Return raw socket listening for 802.1X packets on `ifname` interface.
       The socket is configured for multicast mode on EAP_MULTICAST_ADDR.
       Specify `promisc` to enable promiscuous mode instead.
       Provide `poll` object to register socket to it POLLIN events.
    """
    s = socket.socket(
        socket.PF_PACKET,  # pylint:disable=no-member
        socket.SOCK_RAW,
        socket.htons(ETH_P_PAE))
    s.bind((ifname, 0))
    addsockaddr(s, None if promisc else EAP_MULTICAST_ADDR)
    if poll is not None:
        poll.register(s, select.POLLIN)  # pylint:disable=no-member
    return s


def getifname(sock):
    """Return interface name of `sock`"""
    return sock.getsockname()[0]


def getifaddr(ifname):
    """Return IP addr of `ifname` interface in 1.2.3.4 notation
       or None if no IP is assigned or other IOError occurs.
    """
    # pylint:disable=attribute-defined-outside-init
    ifreq = "%-32s" % (ifname + "\0")
    try:
        result = ioctl(socket.socket(), SIOCGIFADDR, ifreq)
    except IOError:
        return None
    return socket.inet_ntoa(result[20:24])


def getifhwaddr(ifname):
    """Return MAC address for `ifname` as a packed string."""
    with open("/sys/class/net/%s/address" % ifname) as f:
        s = f.readline()
    octets = s.split(':')
    return ''.join(chr(int(x, 16)) for x in octets)


def getdefaultgatewayaddr():
    """Return IP of default route gateway (next hop) in 1.2.3.4 notation
       or None if there is not default route.
    """
    search = re.compile(r"^\S+\s+00000000\s+([0-9a-fA-F]{8})").search
    with open("/proc/net/route") as f:
        for line in f:
            m = search(line)
            if m:
                hexaddr = m.group(1)
                octets = (hexaddr[i:i + 2] for i in xrange(0, 7, 2))
                ipaddr = '.'.join(str(int(octet, 16)) for octet in octets)
                return ipaddr

### Ping

def ipchecksum(packet):
    """Return IP checksum of `packet`"""
    # c.f. https://tools.ietf.org/html/rfc1071
    arr = array.array('H', packet + '\0' if len(packet) % 2 else packet)
    chksum = sum(arr)
    chksum = (chksum >> 16) + (chksum & 0xffff)  # add high and low 16 bits
    chksum += chksum >> 16  # add carry
    chksum = ~chksum & 0xffff  # invert and truncate
    return socket.htons(chksum)  # per RFC 1071


def pingaddr(ipaddr, data='', timeout=1.0, strict=False):
    """Return True if `ipaddr` replies to an ICMP ECHO request within
       `timeout` seconds else False. Provide optional `data` to include in
       the request. Any reply from `ipaddr` will suffice. Use `strict` to
       accept only a reply matching the request.
    """
    # pylint:disable=too-many-locals
    # construct packet
    if len(data) > 2000:
        raise ValueError("data too large")
    icmp_struct = struct.Struct("!BBHHH")
    echoid = os.getpid() & 0xffff
    seqnum = random.randint(0, 0xffff)
    chksum = ipchecksum(icmp_struct.pack(8, 0, 0, echoid, seqnum) + data)
    packet = icmp_struct.pack(8, 0, chksum, echoid, seqnum) + data
    # send it and check reply
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    sock.sendto(packet, (ipaddr, 1))
    t0 = time.time()
    while time.time() - t0 < timeout:
        ready, __, __ = select.select([sock], (), (), timeout)
        if not ready:
            return False
        packet, peer = sock.recvfrom(2048)
        if peer[0] != ipaddr:
            continue
        if not strict:
            return True
        # verify it's a reply to the packet we just sent
        packet = packet[20:]  # strip IP header
        fields = icmp_struct.unpack(packet[:8])
        theirs = fields[-2:] + (packet[8:],)
        if theirs == (echoid, seqnum, data):
            return True
    return False

### Helpers

def strbuf(buf):
    """Return `buf` formatted as a hex dump (like tcpdump -xx)."""
    out = []
    for i in xrange(0, len(buf), 16):
        octets = (ord(x) for x in buf[i:i + 16])
        pairs = []
        for octet in octets:
            pad = '' if len(pairs) % 2 else ' '
            pairs.append("%s%02x" % (pad, octet))
        out.append("0x%04x: %s" % (i, '' .join(pairs)))
    return '\n'.join(out)


def strmac(mac):
    """Return packed string `mac` formatted like aa:bb:cc:dd:ee:ff."""
    return ':'.join("%02x" % ord(b) for b in mac[:6])


def strexc():
    """Return current exception formatted as a single line suitable
       for logging.
    """
    try:
        exc_type, exc_value, tb = sys.exc_info()
        if exc_type is None:
            return ''
        # find last frame in this script
        lineno, func = 0, ''
        for frame in traceback.extract_tb(tb):
            if frame[0] != __file__:
                break
            lineno, func = frame[1:3]
        return "exception in %s line %s (%s: %s)" % (
            func, lineno, exc_type.__name__, exc_value)
    finally:
        del tb


def killpidfile(pidfile, signum):
    """Send `signum` to PID recorded in `pidfile`.
       Return PID if successful, else return None.
    """
    try:
        with open(pidfile) as f:
            pid = int(f.readline())
        os.kill(pid, signum)
        return pid
    except (EnvironmentError, ValueError):
        pass


def checkpidfile(pidfile):
    """Check whether a process is running with the PID in `pidfile`.
       Return PID if successful, else return None.
    """
    return killpidfile(pidfile, 0)


def safe_unlink(path):
    """rm -f `path`"""
    try:
        os.unlink(path)
    except EnvironmentError:
        pass


def writepidfile(pidfile):
    """Write current pid to `pidfile`."""
    with open(pidfile, 'w') as f:
        f.write("%s\n" % os.getpid())

    # NOTE: called on normal Python exit, but not on SIGTERM.
    @atexit.register
    def removepidfile(_remove=os.remove):  # pylint:disable=unused-variable
        try:
            _remove(pidfile)
        except Exception:  # pylint:disable=broad-except
            pass


def daemonize():
    """Convert process into a daemon."""
    if os.fork():
        sys.exit(0)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    if os.fork():
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    nullin = open('/dev/null', 'r')
    nullout = open('/dev/null', 'a+')
    nullerr = open('/dev/null', 'a+', 0)
    os.dup2(nullin.fileno(), sys.stdin.fileno())
    os.dup2(nullout.fileno(), sys.stdout.fileno())
    os.dup2(nullerr.fileno(), sys.stderr.fileno())


def make_logger(use_syslog=False, debug=False):
    """Return new logging.Logger object."""
    if use_syslog:
        formatter = logging.Formatter("eap_proxy[%(process)d]: %(message)s")
        formatter.formatException = lambda *__: ''  # no stack trace to syslog
        SysLogHandler = logging.handlers.SysLogHandler
        handler = SysLogHandler("/dev/log", facility=SysLogHandler.LOG_LOCAL7)
        handler.setFormatter(formatter)
    else:
        formatter = logging.Formatter("[%(asctime)s]: %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

    logger = logging.getLogger("eap_proxy")
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

### EdgeOS


class EdgeOS(object):
    def __init__(self, log):
        self.log = log

    def run(self, *args):
        try:
            return 0, subprocess.check_output(args)
        except subprocess.CalledProcessError as ex:
            self.log.warn("%s exited %d", args, ex.returncode)
            return ex.returncode, ex.output

    def run_vyatta_interfaces(self, name, *args):
        self.run(
            "/opt/vyatta/sbin/vyatta-interfaces.pl", "--dev", name, *args)

    def restart_dhclient(self, name):
        # This isn't working:
        # self.run_vyatta_interfaces(name, "--dhcp", "release")
        # self.run_vyatta_interfaces(name, "--dhcp", "renew")
        # The "renew" command emits:
        #   eth0.0 is not using DHCP to get an IP address
        # So we emulate it ourselves.
        self.stop_dhclient(name)
        self.start_dhclient(name)

    @staticmethod
    def dhclient_pathnames(ifname):
        """Return tuple of (-cf, -pf, and -lf) arg values for dhclient."""
        filename = ifname.replace('.', '_')
        return (
            "/var/run/dhclient_%s.conf" % filename,    # -cf
            "/var/run/dhclient_%s.pid" % filename,     # -pf
            "/var/run/dhclient_%s.leases" % filename)  # -lf

    def stop_dhclient(self, ifname):
        """Stop dhclient on `ifname` interface."""
        # Emulates vyatta-interfaces.pl's behavior
        cf, pf, lf = self.dhclient_pathnames(ifname)
        self.run(
            "/sbin/dhclient", "-q",
            "-cf", cf,
            "-pf", pf,
            "-lf", lf,
            "-r", ifname)
        safe_unlink(pf)

    def start_dhclient(self, ifname):
        """Start dhclient on `ifname` interface"""
        # Emulates vyatta-interfaces.pl's behavior
        cf, pf, lf = self.dhclient_pathnames(ifname)
        killpidfile(pf, signal.SIGTERM)
        safe_unlink(pf)
        self.run(
            "/sbin/dhclient", "-q", "-nw",
            "-cf", cf,
            "-pf", pf,
            "-lf", lf,
            ifname)

    def setmac(self, ifname, mac):
        """Set interface `ifname` mac to `mac`, which may be either a packed
           string or in "aa:bb:cc:dd:ee:ff" format."""
        # untested, perhaps I should use /bin/ip or ioctl instead.
        if len(mac) == 6:
            mac = strmac(mac)
        self.run_vyatta_interfaces(ifname, "--set-mac", mac)

    @staticmethod
    def getmac(ifname):
        """Return MAC address for `ifname` as a packed string."""
        return getifhwaddr(ifname)

### EAP frame/packet decoding
# c.f. https://github.com/the-tcpdump-group/tcpdump/blob/master/print-eap.c

class EAPFrame(namedtuple("EAPFrame", "dst src version type length packet")):
    __slots__ = ()
    _struct = struct.Struct("!6s6sHBBH")  # includes ethernet header
    TYPE_PACKET = 0
    TYPE_START = 1
    TYPE_LOGOFF = 2
    TYPE_KEY = 3
    TYPE_ENCAP_ASF_ALERT = 4
    _types = {
        TYPE_PACKET: "EAP packet",
        TYPE_START: "EAPOL start",
        TYPE_LOGOFF: "EAPOL logoff",
        TYPE_KEY: "EAPOL key",
        TYPE_ENCAP_ASF_ALERT: "Encapsulated ASF alert"
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        dst, src, etype, ver, ptype, length = unpack(buf[:size])
        if etype != ETH_P_PAE:
            raise ValueError("invalid ethernet type: 0x%04x" % etype)
        if ptype == cls.TYPE_PACKET:
            packet = EAPPacket.from_buf(buf[size:size + length])
        else:
            packet = None
        return cls(dst, src, ver, ptype, length, packet)

    @property
    def type_name(self):
        return self._types.get(self.type, "???")

    @property
    def is_start(self):
        return self.type == self.TYPE_START

    @property
    def is_logoff(self):
        return self.type == self.TYPE_LOGOFF

    @property
    def is_success(self):
        return self.packet and self.packet.is_success

    def __str__(self):
        return "%s > %s, %s (%d) v%d, len %d%s" % (
            strmac(self.src), strmac(self.dst),
            self.type_name, self.type, self.version, self.length,
            ", " + str(self.packet) if self.packet else '')


class EAPPacket(namedtuple("EAPPacket", "code id length data")):
    __slots__ = ()
    _struct = struct.Struct("!BBH")
    REQUEST, RESPONSE, SUCCESS, FAILURE = 1, 2, 3, 4
    _codes = {
        REQUEST: "Request",
        RESPONSE: "Response",
        SUCCESS: "Success",
        FAILURE: "Failure"
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        code, id_, length = unpack(buf[:size])
        data = buf[size:size + length - 4]
        return cls(code, id_, length, data)

    @property
    def code_name(self):
        return self._codes.get(self.code, "???")

    @property
    def is_success(self):
        return self.code == self.SUCCESS

    def __str__(self):
        return "%s (%d) id %d, len %d [%d]" % (
            self.code_name, self.code, self.id, self.length, len(self.data))

### EAP Proxy

class EAPProxy(object):

    def __init__(self, args, log):
        self.args = args
        self.os = EdgeOS(log)
        self.log = log

    def proxy_forever(self):
        log = self.log
        while True:
            try:
                log.info("proxy_loop starting")
                self.proxy_loop()
            except KeyboardInterrupt:
                return
            except Exception as ex:  # pylint:disable=broad-except
                log.warn("%s; restarting in 10 seconds", strexc(), exc_info=ex)
            else:
                log.warn("proxy_loop exited; restarting in 10 seconds")
            time.sleep(10)

    def proxy_loop(self):
        args = self.args
        poll = select.poll()  # pylint:disable=no-member
        s_rtr = rawsocket(args.if_rtr, poll=poll, promisc=args.promiscuous)
        s_wan = rawsocket(args.if_wan, poll=poll, promisc=args.promiscuous)
        socks = {s.fileno(): s for s in (s_rtr, s_wan)}
        on_poll_event = partial(self.on_poll_event, s_rtr=s_rtr, s_wan=s_wan)

        while True:
            ready = poll.poll()
            for fd, event in ready:
                on_poll_event(socks[fd], event)

    def on_poll_event(self, sock_in, event, s_rtr, s_wan):
        log = self.log
        ifname = getifname(sock_in)
        if event != select.POLLIN:  # pylint:disable=no-member
            raise IOError("[%s] unexpected poll event: %d", ifname, event)

        buf = sock_in.recv(2048)

        if self.args.debug_packets:
            log.debug("%s: recv %d bytes:\n%s", ifname, len(buf), strbuf(buf))

        eap = EAPFrame.from_buf(buf)
        log.debug("%s: %s", ifname, eap)

        if sock_in == s_rtr:
            sock_out = s_wan
            self.on_router_eap(eap)
            if self.should_ignore_router_eap(eap):
                log.debug("%s: ignoring %s", ifname, eap)
                return
        else:
            sock_out = s_rtr
            self.on_wan_eap(eap)

        log.info("%s: %s > %s", ifname, eap, getifname(sock_out))
        nbytes = sock_out.send(buf)
        log.debug("%s: sent %d bytes", getifname(sock_out), nbytes)


    def should_ignore_router_eap(self, eap):
        args = self.args
        if args.ignore_start and eap.is_start:
            return True
        if args.ignore_logoff and eap.is_logoff:
            return True
        if args.ignore_when_wan_up:
            return self.check_wan_is_up()
        return False

    def on_router_eap(self, eap):
        args = self.args
        if not args.set_mac:
            return

        if_vlan = args.if_wan + ".0"
        if self.os.getmac(if_vlan) == eap.src:
            return

        self.log.info("%s: setting mac to %s", if_vlan, strmac(eap.src))
        self.os.setmac(if_vlan, eap.src)

    def on_wan_eap(self, eap):
        if not self.should_restart_dhcp(eap):
            return
        if_vlan = self.args.if_wan + ".0"
        self.log.info("%s: restarting dhclient", if_vlan)
        self.os.restart_dhclient(if_vlan)

    def should_restart_dhcp(self, eap):
        if self.args.restart_dhcp and eap.is_success:
            return not self.check_wan_is_up()
        return False

    def check_wan_is_up(self):
        args, log = self.args, self.log
        if_vlan = args.if_wan + ".0"
        ipaddr = getifaddr(if_vlan)
        if ipaddr:
            log.debug("%s: %s", if_vlan, ipaddr)
            return self.ping_gateway() if args.ping_gateway else True
        log.debug("%s: no IP address", if_vlan)
        return False

    def ping_gateway(self):
        log = self.log
        ipaddr = getdefaultgatewayaddr()
        if not ipaddr:
            log.debug("ping: no default route gateway")
            return False
        rv = pingaddr(ipaddr)
        log.debug("ping: %s %s", ipaddr, "success" if rv else "failed")
        return rv

### Main

def parse_args():
    p = argparse.ArgumentParser("eap_proxy")

    # interface arguments
    p.add_argument(
        "if_wan", metavar="IF_WAN", help="interface of the AT&T ONT/WAN")
    p.add_argument(
        "if_rtr", metavar="IF_ROUTER", help="interface of the AT&T router")

    # checking whether WAN is up
    g = p.add_argument_group("checking whether WAN is up")
    g.add_argument(
        "--ping-gateway", action="store_true", help=
        "normally the WAN is considered up if IF_WAN.0 has an IP address; "
        "this option additionally requires that there is a default route "
        "gateway that responds to a ping")

    # ignoring packet options
    g = p.add_argument_group("ignoring router packets")
    g.add_argument(
        "--ignore-when-wan-up", action="store_true", help=
        "ignore router packets when WAN is up (see --ping-gateway)")
    g.add_argument(
        "--ignore-start", action="store_true", help=
        "always ignore EAPOL-Start from router")
    g.add_argument(
        "--ignore-logoff", action="store_true", help=
        "always ignore EAPOL-Logoff from router")

    # configuring IF_WAN.0 VLAN options
    g = p.add_argument_group("configuring IF_WAN.0 VLAN")
    g.add_argument(
        "--restart-dhcp", action="store_true", help=
        "check whether WAN is up after receiving EAP-Success on IF_WAN "
        "(see --ping-gateway); if not, restart dhclient on IF_WAN.0")
    g.add_argument(
        "--set-mac", action="store_true", help=
        "set IF_WAN.0's MAC (ether) address to router's MAC address")

    # daemonization options
    g = p.add_argument_group("daemonization")
    g.add_argument(
        "--daemon", action="store_true", help=
        "become a daemon; implies --syslog")
    g.add_argument("--pidfile", help="record pid to PIDFILE")
    g.add_argument(
        "--syslog", action="store_true", help=
        "log to syslog instead of stderr")

    # debugging options
    g = p.add_argument_group("debugging")
    g.add_argument(
        "--promiscuous", action="store_true", help=
        "place interfaces into promiscuous mode instead of multicast")
    g.add_argument(
        "--debug", action="store_true", help=
        "enable debug-level logging")
    g.add_argument(
        "--debug-packets", action="store_true", help=
        "print packets in hex format to assist with debugging; "
        "implies --debug")

    args = p.parse_args()
    if args.daemon:
        args.syslog = True
    if args.debug_packets:
        if args.syslog:
            p.error("--debug-packets not allowed with --syslog")
        args.debug = True
    return args


def main():
    args = parse_args()
    log = make_logger(args.syslog, args.debug)

    if args.pidfile:
        pid = checkpidfile(args.pidfile)
        if pid:
            log.error("eap_proxy already running with pid %s?", pid)
            return 1

    if args.daemon:
        try:
            daemonize()
        except Exception:  # pylint:disable=broad-except
            log.exception("could not become daemon: %s", strexc())
            return 1

    # ensure cleanup (atexit, etc) occurs when we're killed via SIGTERM
    def on_sigterm(signum, __):
        log.info("exiting on signal %d", signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_sigterm)

    if args.pidfile:
        try:
            writepidfile(args.pidfile)
        except EnvironmentError:  # pylint:disable=broad-except
            log.exception("could not write pidfile: %s", strexc())

    EAPProxy(args, log).proxy_forever()


if __name__ == "__main__":
    sys.exit(main())
