#!/usr/bin/env python
"""
usage: eap_proxy [-h] [--ping-gateway] [--ping-ip PING_IP]
                 [--ignore-when-wan-up] [--ignore-start] [--ignore-logoff]
                 [--restart-dhcp] [--set-mac] [--vlan-id VLAN_ID] [--daemon]
                 [--pidfile PIDFILE] [--syslog] [--run-as USER[:GROUP]]
                 [--promiscuous] [--debug] [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface of the AT&T ONT/WAN
  IF_ROUTER             interface of the AT&T router

optional arguments:
  -h, --help            show this help message and exit

checking whether WAN is up:
  --ping-gateway        normally the WAN is considered up if the IF_WAN VLAN
                        has an address; this option additionally requires that
                        there is a route via IF_WAN with a gateway (next-hop)
                        that responds to a ping
  --ping-ip PING_IP     normally the WAN is considered up if the IF_WAN VLAN
                        has an address; this option additionally requires that
                        PING_IP responds to a ping

ignoring router packets:
  --ignore-when-wan-up  ignore router packets when WAN is up (see --ping-
                        gateway)
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

configuring IF_WAN VLAN:
  --restart-dhcp        check whether WAN is up after receiving EAP-Success on
                        IF_WAN VLAN (see --ping-gateway); if not, restart
                        dhclient on IF_WAN VLAN
  --set-mac             set IF_WAN VLAN MAC (ether) address to router's MAC
                        address
  --vlan-id VLAN_ID     set IF_WAN VLAN ID (default is 0)

process management:
  --daemon              fork into background and attempt to run forever until
                        killed; implies --syslog
  --pidfile PIDFILE     record pid to PIDFILE
  --syslog              log to syslog instead of stderr
  --run-as USER[:GROUP]
                        switch to USER[:GROUP] after opening sockets;
                        incompatible with --daemon

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
import pwd, grp  # pylint:disable=multiple-imports
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

### Constants

EAP_MULTICAST_ADDR = (0x01, 0x80, 0xC2, 0x00, 0x00, 0x03)
ETH_P_PAE = 0x888E  # IEEE 802.1X (Port Access Entity)
IFF_PROMISC = 0x100
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
SIOCGIFADDR = 0x8915
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SOL_PACKET = 263

### Python 2 / 3 compatibility

PY3 = sys.version_info[0] == 3

try:
    xrange
except NameError:
    xrange = range  # pylint:disable=redefined-builtin


def to_utf8(s):
    return s if isinstance(s, bytes) else s.encode("utf8")


try:
    if_nametoindex = socket.if_nametoindex  # as of Python 3.3
except AttributeError:
    _if_nametoindex = ctypes.CDLL(ctypes.util.find_library("c")).if_nametoindex

    def if_nametoindex(ifname):
        return _if_nametoindex(to_utf8(ifname))


### Sockets / Network Interfaces


class struct_packet_mreq(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("mr_ifindex", ctypes.c_int),
        ("mr_type", ctypes.c_ushort),
        ("mr_alen", ctypes.c_ushort),
        ("mr_address", ctypes.c_ubyte * 8),
    )


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


def rawsocket(ifname, promisc=False):
    """Return raw socket listening for 802.1X packets on `ifname` interface.
       The socket is configured for multicast mode on EAP_MULTICAST_ADDR.
       Specify `promisc` to enable promiscuous mode instead.
    """
    s = socket.socket(
        socket.PF_PACKET,  # pylint:disable=no-member
        socket.SOCK_RAW,
        socket.htons(ETH_P_PAE),
    )
    s.bind((ifname, 0))
    addsockaddr(s, None if promisc else EAP_MULTICAST_ADDR)
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
    octets = s.split(":")
    return "".join(chr(int(x, 16)) for x in octets)


def getifgateway(ifname):
    """Return IP of `ifname`'s gateway (next hop) in 1.2.3.4 notation or None
       if no route exists for `ifname`. If multiple routes exist for `ifname`,
       the next hop is returned for that with the widest netmask.
    """
    search = re.compile(
        "^"
        + re.escape(ifname)
        + r"""\s+
        [0-9a-fA-F]{8}\s+    # Destination
        ([0-9a-fA-F]{8})\s+  # Gateway (1)
        [0-9a-fA-F]+\s+      # Flags
        [0-9a-fA-F]+\s+      # RefCnt
        [0-9a-fA-F]+\s+      # Use
        [0-9a-fA-F]+\s+      # Metric
        ([0-9a-fA-F]{8})\s+  # Mask    (2)
        """,
        re.X,
    ).search

    def hex_to_octets(arg):
        # the order of the hex octets in arg is dependent on host byte order,
        # but struct.pack handles that when packing into a long.
        ipaddr = socket.inet_ntoa(struct.pack("=L", int(arg, 16)))
        return tuple(int(x) for x in ipaddr.split("."))

    best_gateway, best_mask = None, None

    with open("/proc/net/route") as f:
        for line in f:
            m = search(line)
            if not m:
                continue
            gateway, mask = hex_to_octets(m.group(1)), hex_to_octets(m.group(2))
            if gateway == (0, 0, 0, 0):
                continue
            if best_mask is None or mask < best_mask:
                best_gateway, best_mask = gateway, mask
    return ".".join(str(x) for x in best_gateway) if best_gateway else None


### Ping


def ipchecksum(packet):
    """Return IP checksum of `packet`"""
    # c.f. https://tools.ietf.org/html/rfc1071
    arr = array.array("H", packet + "\0" if len(packet) % 2 else packet)
    chksum = sum(arr)
    chksum = (chksum >> 16) + (chksum & 0xFFFF)  # add high and low 16 bits
    chksum += chksum >> 16  # add carry
    chksum = ~chksum & 0xFFFF  # invert and truncate
    return socket.htons(chksum)  # per RFC 1071


def pingaddr(ipaddr, data="", timeout=1.0, strict=False):
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
    echoid = os.getpid() & 0xFFFF
    seqnum = random.randint(0, 0xFFFF)
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
    tobyte = (lambda x: x) if (PY3 and isinstance(buf, bytes)) else ord
    for i in xrange(0, len(buf), 16):
        octets = (tobyte(x) for x in buf[i : i + 16])
        pairs = []
        for octet in octets:
            pad = "" if len(pairs) % 2 else " "
            pairs.append("%s%02x" % (pad, octet))
        out.append("0x%04x: %s" % (i, "".join(pairs)))
    return "\n".join(out)


def strmac(mac):
    """Return packed string `mac` formatted like aa:bb:cc:dd:ee:ff."""
    tobyte = (lambda x: x) if (PY3 and isinstance(mac, bytes)) else ord
    return ":".join("%02x" % tobyte(b) for b in mac[:6])


def strexc():
    """Return current exception formatted as a single line suitable
       for logging.
    """
    try:
        exc_type, exc_value, tb = sys.exc_info()
        if exc_type is None:
            return ""
        # find last frame in this script
        lineno, func = 0, ""
        for frame in traceback.extract_tb(tb):
            if frame[0] != __file__:
                break
            lineno, func = frame[1:3]
        return "exception in %s line %s (%s: %s)" % (
            func,
            lineno,
            exc_type.__name__,
            exc_value,
        )
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
    with open(pidfile, "w") as f:
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
    nullin = open("/dev/null", "r")
    nullout = open("/dev/null", "a+")
    nullerr = open("/dev/null", "a+", 0)
    os.dup2(nullin.fileno(), sys.stdin.fileno())
    os.dup2(nullout.fileno(), sys.stdout.fileno())
    os.dup2(nullerr.fileno(), sys.stderr.fileno())


def run_as(username, groupname=""):
    """Switch process to run as `username` and optionally `groupname`."""
    pw = pwd.getpwnam(username)
    uid = pw.pw_uid
    gid = grp.getgrnam(groupname).gr_gid if groupname else pw.pw_gid
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def make_logger(use_syslog=False, debug=False):
    """Return new logging.Logger object."""
    if use_syslog:
        formatter = logging.Formatter("eap_proxy[%(process)d]: %(message)s")
        formatter.formatException = lambda *__: ""  # no stack trace to syslog
        SysLogHandler = logging.handlers.SysLogHandler
        handler = SysLogHandler("/dev/log", facility=SysLogHandler.LOG_LOCAL7)
        handler.setFormatter(formatter)
    else:
        formatter = logging.Formatter("[%(asctime)s]: %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

    logger = logging.getLogger("eap_proxy")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
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
        self.run("/opt/vyatta/sbin/vyatta-interfaces.pl", "--dev", name, *args)

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
        filename = ifname.replace(".", "_")
        return (
            "/var/run/dhclient_%s.conf" % filename,  # -cf
            "/var/run/dhclient_%s.pid" % filename,  # -pf
            "/var/run/dhclient_%s.leases" % filename,
        )  # -lf

    def stop_dhclient(self, ifname):
        """Stop dhclient on `ifname` interface."""
        # Emulates vyatta-interfaces.pl's behavior
        cf, pf, lf = self.dhclient_pathnames(ifname)
        self.run("/sbin/dhclient", "-q", "-cf", cf, "-pf", pf, "-lf", lf, "-r", ifname)
        safe_unlink(pf)

    def start_dhclient(self, ifname):
        """Start dhclient on `ifname` interface"""
        # Emulates vyatta-interfaces.pl's behavior
        cf, pf, lf = self.dhclient_pathnames(ifname)
        killpidfile(pf, signal.SIGTERM)
        safe_unlink(pf)
        self.run("/sbin/dhclient", "-q", "-nw", "-cf", cf, "-pf", pf, "-lf", lf, ifname)

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
        TYPE_ENCAP_ASF_ALERT: "Encapsulated ASF alert",
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        dst, src, etype, ver, ptype, length = unpack(buf[:size])
        if etype != ETH_P_PAE:
            raise ValueError("invalid ethernet type: 0x%04x" % etype)
        if ptype == cls.TYPE_PACKET:
            packet = EAPPacket.from_buf(buf[size : size + length])
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
            strmac(self.src),
            strmac(self.dst),
            self.type_name,
            self.type,
            self.version,
            self.length,
            ", " + str(self.packet) if self.packet else "",
        )


class EAPPacket(namedtuple("EAPPacket", "code id length data")):
    __slots__ = ()
    _struct = struct.Struct("!BBH")
    REQUEST, RESPONSE, SUCCESS, FAILURE = 1, 2, 3, 4
    _codes = {
        REQUEST: "Request",
        RESPONSE: "Response",
        SUCCESS: "Success",
        FAILURE: "Failure",
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        code, id_, length = unpack(buf[:size])
        data = buf[size : size + length - 4]
        return cls(code, id_, length, data)

    @property
    def code_name(self):
        return self._codes.get(self.code, "???")

    @property
    def is_success(self):
        return self.code == self.SUCCESS

    def __str__(self):
        return "%s (%d) id %d, len %d [%d]" % (
            self.code_name,
            self.code,
            self.id,
            self.length,
            len(self.data),
        )


### EAP Proxy


class EAPProxy(object):
    _poll_events = {
        select.POLLERR: "POLLERR",
        select.POLLHUP: "POLLHUP",
        select.POLLNVAL: "POLLNVAL",
    }

    def __init__(self, args, log):
        self.args = args
        self.os = EdgeOS(log)
        self.log = log
        self.s_rtr = rawsocket(args.if_rtr, promisc=args.promiscuous)
        self.s_wan = rawsocket(args.if_wan, promisc=args.promiscuous)

    def proxy_loop(self):
        poll = select.poll()
        poll.register(self.s_rtr, select.POLLIN)  # pylint:disable=no-member
        poll.register(self.s_wan, select.POLLIN)  # pylint:disable=no-member
        socks = {s.fileno(): s for s in (self.s_rtr, self.s_wan)}
        while True:
            ready = poll.poll()
            for fd, event in ready:
                self.on_poll_event(socks[fd], event)

    def on_poll_event(self, sock_in, event):
        log = self.log
        ifname = getifname(sock_in)
        if event != select.POLLIN:  # pylint:disable=no-member
            ename = self._poll_events.get(event, "???")
            raise IOError(
                "[%s] unexpected poll event: %s (%d)" % (ifname, ename, event)
            )

        buf = sock_in.recv(2048)

        if self.args.debug_packets:
            log.debug("%s: recv %d bytes:\n%s", ifname, len(buf), strbuf(buf))

        eap = EAPFrame.from_buf(buf)
        log.debug("%s: %s", ifname, eap)

        if sock_in == self.s_rtr:
            sock_out = self.s_wan
            self.on_router_eap(eap)
            if self.should_ignore_router_eap(eap):
                log.debug("%s: ignoring %s", ifname, eap)
                return
        else:
            sock_out = self.s_rtr
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

        if_vlan = "%s.%d" % (args.if_wan, args.vlan_id)
        if self.os.getmac(if_vlan) == eap.src:
            return

        self.log.info("%s: setting mac to %s", if_vlan, strmac(eap.src))
        self.os.setmac(if_vlan, eap.src)

    def on_wan_eap(self, eap):
        if not self.should_restart_dhcp(eap):
            return
        args = self.args
        if_vlan = "%s.%d" % (args.if_wan, args.vlan_id)
        self.log.info("%s: restarting dhclient", if_vlan)
        self.os.restart_dhclient(if_vlan)

    def should_restart_dhcp(self, eap):
        if self.args.restart_dhcp and eap.is_success:
            return not self.check_wan_is_up()
        return False

    def check_wan_is_up(self):
        args, log = self.args, self.log
        if_vlan = "%s.%d" % (args.if_wan, args.vlan_id)
        ipaddr = getifaddr(if_vlan)
        if ipaddr:
            log.debug("%s: %s", if_vlan, ipaddr)
            if args.ping_gateway:
                return self.ping_wan_gateway(if_vlan)
            if args.ping_ip:
                return self.ping_ipaddr(args.ping_ip)
            return True
        log.debug("%s: no IP address", if_vlan)
        return False

    def ping_wan_gateway(self, if_vlan):
        ipaddr = getifgateway(if_vlan)
        if not ipaddr:
            self.log.debug("ping: no gateway for %s", if_vlan)
            return False
        return self.ping_ipaddr(ipaddr)

    def ping_ipaddr(self, ipaddr):
        rv = pingaddr(ipaddr)
        self.log.debug("ping: %s %s", ipaddr, "success" if rv else "failed")
        return rv


### Main


def parse_args():
    p = argparse.ArgumentParser("eap_proxy")

    # interface arguments
    p.add_argument("if_wan", metavar="IF_WAN", help="interface of the AT&T ONT/WAN")
    p.add_argument("if_rtr", metavar="IF_ROUTER", help="interface of the AT&T router")

    # checking whether WAN is up
    g = p.add_argument_group("checking whether WAN is up")
    g.add_argument(
        "--ping-gateway",
        action="store_true",
        help="normally the WAN is considered up if the IF_WAN VLAN has an address; "
        "this option additionally requires that there is a route via IF_WAN "
        "with a gateway (next-hop) that responds to a ping",
    )
    g.add_argument(
        "--ping-ip",
        help="normally the WAN is considered up if the IF_WAN VLAN has an address; "
        "this option additionally requires that PING_IP responds to a ping",
    )

    # ignoring packet options
    g = p.add_argument_group("ignoring router packets")
    g.add_argument(
        "--ignore-when-wan-up",
        action="store_true",
        help="ignore router packets when WAN is up (see --ping-gateway)",
    )
    g.add_argument(
        "--ignore-start",
        action="store_true",
        help="always ignore EAPOL-Start from router",
    )
    g.add_argument(
        "--ignore-logoff",
        action="store_true",
        help="always ignore EAPOL-Logoff from router",
    )

    # configuring IF_WAN VLAN options
    g = p.add_argument_group("configuring IF_WAN VLAN")
    g.add_argument(
        "--restart-dhcp",
        action="store_true",
        help="check whether WAN is up after receiving EAP-Success on IF_WAN VLAN "
        "(see --ping-gateway); if not, restart dhclient on IF_WAN VLAN",
    )
    g.add_argument(
        "--set-mac",
        action="store_true",
        help="set IF_WAN VLAN MAC (ether) address to router's MAC address",
    )
    g.add_argument(
        "--vlan-id", type=int, default=0, help="set IF_WAN VLAN ID (default is 0)"
    )

    # process management options
    g = p.add_argument_group("process management")
    g.add_argument(
        "--daemon",
        action="store_true",
        help="fork into background and attempt to run forever until killed; "
        "implies --syslog",
    )
    g.add_argument("--pidfile", help="record pid to PIDFILE")
    g.add_argument(
        "--syslog", action="store_true", help="log to syslog instead of stderr"
    )
    g.add_argument(
        "--run-as",
        metavar="USER[:GROUP]",
        help="switch to USER[:GROUP] after opening sockets; "
        "incompatible with --daemon",
    )

    # debugging options
    g = p.add_argument_group("debugging")
    g.add_argument(
        "--promiscuous",
        action="store_true",
        help="place interfaces into promiscuous mode instead of multicast",
    )
    g.add_argument("--debug", action="store_true", help="enable debug-level logging")
    g.add_argument(
        "--debug-packets",
        action="store_true",
        help="print packets in hex format to assist with debugging; " "implies --debug",
    )

    args = p.parse_args()
    if args.ping_gateway and args.ping_ip:
        p.error("--ping-gateway not allowed with --ping-ip")
    if args.run_as:
        if args.daemon:
            p.error("--run-as not allowed with --daemon")
        user, __, group = args.run_as.partition(":")
        args.run_as = (user, group)
    if args.daemon:
        args.syslog = True
    if args.debug_packets:
        if args.syslog:
            p.error("--debug-packets not allowed with --syslog")
        args.debug = True
    return args


def proxy_loop(args, log):
    proxy = EAPProxy(args, log)
    if args.run_as:
        try:
            run_as(*args.run_as)
            log.debug("running as uid:gid %d:%d" % (os.getuid(), os.getgid()))
        except Exception:  # pylint:disable=broad-except
            log.exception("could not switch user/group: %s", strexc())
            return 1
    log.info("starting proxy_loop")
    proxy.proxy_loop()
    return 0


def proxy_loop_forever(args, log):
    while True:
        try:
            proxy_loop(args, log)
        except KeyboardInterrupt:
            return 0
        except Exception as ex:  # pylint:disable=broad-except
            log.warn("%s; restarting in 10 seconds", strexc(), exc_info=ex)
        else:
            log.warn("proxy_loop exited; restarting in 10 seconds")
        time.sleep(10)


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

    proxy = proxy_loop_forever if args.daemon else proxy_loop
    return proxy(args, log)


if __name__ == "__main__":
    sys.exit(main())
