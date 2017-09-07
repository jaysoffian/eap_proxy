#!/usr/bin/env python
"""
Inspired by 1x_prox as posted here:

    http://www.dslreports.com/forum/r30693618-

    AT&T Residential Gateway Bypass - True bridge mode!

usage: eap_proxy [-h] [--ignore-wan-has-ip] [--ignore-wan-ping-gateway]
                 [--ignore-start] [--ignore-logoff] [--restart-dhcp]
                 [--set-mac] [--daemon] [--pidfile PIDFILE] [--syslog]
                 [--promiscuous] [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface of the AT&T ONT/WAN
  IF_ROUTER             interface of the AT&T router

optional arguments:
  -h, --help            show this help message and exit

ignoring router packets:
  --ignore-wan-has-ip   ignore router packets if IF_WAN.0 has an IP address
                        assigned
  --ignore-wan-ping-gateway
                        ignore router packets if IF_WAN.0 has a reachable
                        default gateway
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

configuring IF_WAN.0 VLAN:
  --restart-dhcp        restart IF_WAN.0 dhclient after receiving EAP-Success
                        if IF_WAN.0 does not have a reachable default gateway
  --set-mac             set IF_WAN.0 MAC to router's MAC

daemonization:
  --daemon              become a daemon; implies --syslog
  --pidfile PIDFILE     record pid to PIDFILE
  --syslog              log to syslog instead of stderr

debugging:
  --promiscuous         place interfaces into promiscuous mode instead of
                        multicast
  --debug-packets       print packets in hex format to assist with debugging
"""
# pylint:disable=invalid-name,missing-docstring
import argparse
import atexit
import ctypes
import ctypes.util
import logging
import logging.handlers
import os
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

ETH_P_PAE = 0x888e  # 802.1x
IFF_PROMISC = 0x100
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
CHECK_VLAN_IF_TTL = 75
SIOCGIFADDR = 0x8915
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SOL_PACKET = 263

### Sockets

class struct_sockaddr(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("sa_family", ctypes.c_ushort),
        ("sa_data", ctypes.c_ubyte * 14))


class struct_sockaddr_in(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_char * 8))


class union_ifr_ifru(ctypes.Union):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("ifr_addr", struct_sockaddr_in),
        ("ifr_hwaddr", struct_sockaddr),
        ("ifr_flags", ctypes.c_short))


class struct_ifreq(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _anonymous_ = ("ifr_ifru",)
    _fields_ = (
        ("ifr_name", ctypes.c_char * 16),
        ("ifr_ifru", union_ifr_ifru))


class struct_packet_mreq(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("mr_ifindex", ctypes.c_int),
        ("mr_type", ctypes.c_ushort),
        ("mr_alen", ctypes.c_ushort),
        ("mr_address", ctypes.c_ubyte * 8))


def enable_multicast(sock):
    # pylint:disable=attribute-defined-outside-init
    mreq = struct_packet_mreq()
    mreq.mr_ifindex = if_nametoindex(if_name(sock))
    mreq.mr_type = PACKET_MR_MULTICAST
    mreq.mr_alen = 6
    mreq.mr_address = (0x01, 0x80, 0xc2, 0x00, 0x00, 0x03)
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    return sock


def enable_promisc(sock):
    # pylint:disable=attribute-defined-outside-init
    ifreq = struct_ifreq()
    ifreq.ifr_name = if_name(sock)
    ioctl(sock, SIOCGIFFLAGS, ifreq)
    ifreq.ifr_flags |= IFF_PROMISC  # pylint:disable=no-member
    ioctl(sock, SIOCSIFFLAGS, ifreq)
    return sock


if_nametoindex = ctypes.CDLL(ctypes.util.find_library('c')).if_nametoindex


def if_name(sock):
    return sock.getsockname()[0]


def if_addr(name):
    """Return IP of `name` interface or None if unassigned or error."""
    # pylint:disable=attribute-defined-outside-init
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)
    ifreq = struct_ifreq()
    ifreq.ifr_name = name
    try:
        ioctl(sock, SIOCGIFADDR, ifreq)
    except IOError:
        return None
    return socket.inet_ntoa(struct.pack("!I", ifreq.ifr_addr.sin_addr))


def if_open(name, poll=None, promisc=False):
    s = socket.socket(
        socket.PF_PACKET,  # pylint:disable=no-member
        socket.SOCK_RAW,
        socket.htons(ETH_P_PAE))
    s.bind((name, 0))
    if promisc:
        enable_promisc(s)
    else:
        enable_multicast(s)
    if poll is not None:
        poll.register(s, select.POLLIN)  # pylint:disable=no-member
    return s


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
    """Return `mac` formatted like aa:bb:cc:dd:ee:ff."""
    return ':'.join("%02x" % ord(b) for b in mac[:6])


def strexc():
    """Return current exception formatted as a single line suitable
       for logging.
    """
    try:
        exc_type, exc_value, tb = sys.exc_info()
        if exc_type is None:
            return ''
        pathname, lineno, func, __ = traceback.extract_tb(tb)[-1]
        filename = os.path.basename(pathname)
        return "%s (%s:%s) %s: %s" % (
            func, filename, lineno, exc_type.__name__, exc_value)
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
    try:
        os.unlink(path)
    except EnvironmentError:
        pass


def writepidfile(pidfile, log=None):
    with open(pidfile, 'w') as f:
        f.write("%s\n" % os.getpid())

    @atexit.register
    def removepidfile(_remove=os.remove):  # pylint:disable=unused-variable
        try:
            _remove(pidfile)
        except Exception:  # pylint:disable=broad-except
            pass

    # atexit doesn't run on SIGTERM, so help it out
    def on_sigterm(signum, frame):  # pylint:disable=unused-argument
        if log is not None:
            log.info("exiting on signal %d", signum)
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, on_sigterm)


def daemonize():
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


def make_logger(use_syslog=False):
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
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger


def dhclient_pathnames(name):
    filename = name.replace('.', '_')
    return (
        "/var/run/dhclient_%s.conf" % filename,
        "/var/run/dhclient_%s.pid" % filename,
        "/var/run/dhclient_%s.leases" % filename)

### EdgeOS

class EdgeOS(object):
    def __init__(self, log):
        self.warn = log.warning

    def run(self, *args):
        try:
            return 0, subprocess.check_output(args)
        except subprocess.CalledProcessError as ex:
            self.warn("%s exited %d", args, ex.returncode)
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

    def stop_dhclient(self, name):
        cf, pf, lf = dhclient_pathnames(name)
        self.run(
            "/sbin/dhclient", "-q",
            "-cf", cf,
            "-pf", pf,
            "-lf", lf,
            "-r", name)
        safe_unlink(pf)

    def start_dhclient(self, name):
        cf, pf, lf = dhclient_pathnames(name)
        killpidfile(pf, signal.SIGTERM)
        safe_unlink(pf)
        self.run(
            "/sbin/dhclient", "-q", "-nw",
            "-cf", cf,
            "-pf", pf,
            "-lf", lf,
            name)

    def setmac(self, name, mac):
        """Set interface `name` mac to `mac`"""
        if len(mac) == 6:
            mac = strmac(mac)
        self.run_vyatta_interfaces(name, "--set-mac", mac)

    def getmac(self, name):  # pylint:disable=no-self-use
        """Return MAC address for `name` as a 6 octet string."""
        with open("/sys/class/net/%s/address" % name) as f:
            s = f.readline()
        octets = s.split(':')
        return ''.join(chr(int(x, 16)) for x in octets)

    def check_interface(self, name):
        ip_addr = "1.2.3.4"  # used for finding default route only
        pattern = r"^%s via ([\d\.]+) dev %s\s" % (
            re.escape(ip_addr),
            re.escape(name))
        search = re.compile(pattern).search
        rc, output = self.run("ip", "route", "get", ip_addr)
        via_ip = None
        for line in output.splitlines():
            m = search(line)
            if m:
                via_ip = m.group(1)
                break
        if not via_ip:
            return False
        rc, output = self.run("ping", "-c", "1", "-w", "1", via_ip)
        return True if rc == 0 else False


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
        self.last_check_vlan_if_result = False
        self.last_check_vlan_if_time = 0
        self.log = log.info
        self.warn = log.warning

    def proxy_forever(self):
        while True:
            try:
                self.log("proxy_loop starting")
                self.proxy_loop()
            except KeyboardInterrupt:
                return
            except Exception as ex:  # pylint:disable=broad-except
                self.warn("%s; restarting in 10 seconds", strexc(), exc_info=ex)
            else:
                self.warn("proxy_loop exited; restarting in 10 seconds")
            time.sleep(10)

    def proxy_loop(self):
        args = self.args
        poll = select.poll()  # pylint:disable=no-member
        s_rtr = if_open(args.if_rtr, poll=poll, promisc=args.promiscuous)
        s_wan = if_open(args.if_wan, poll=poll, promisc=args.promiscuous)
        socks = {s.fileno(): s for s in (s_rtr, s_wan)}
        on_poll_event = partial(self.on_poll_event, s_rtr=s_rtr, s_wan=s_wan)

        while True:
            ready = poll.poll()
            for fd, event in ready:
                on_poll_event(socks[fd], event)

    def on_poll_event(self, sock, event, s_rtr, s_wan):
        name = if_name(sock)
        if event != select.POLLIN:  # pylint:disable=no-member
            raise IOError("[%s] invalid poll event: %d", name, event)

        buf = sock.recv(2048)

        if self.args.debug_packets:
            self.log("%s: recv %d bytes:\n%s", name, len(buf), strbuf(buf))
        else:
            self.log("%s: recv %d bytes", name, len(buf))

        eap = EAPFrame.from_buf(buf)
        self.log("%s: %s", name, eap)

        if sock == s_rtr:
            sock_out = s_wan
            self.on_router_eap(eap)
            if self.should_ignore_router_eap(eap):
                self.log("%s: ignoring %s", name, eap.type_name)
                return
        else:
            sock_out = s_rtr
            self.on_wan_eap(eap)

        sent = sock_out.send(buf)
        self.log("%s: sent %d bytes", if_name(sock_out), sent)


    def should_ignore_router_eap(self, eap):
        args = self.args
        if args.ignore_start and eap.is_start:
            return True
        if args.ignore_logoff and eap.is_logoff:
            return True
        return self.check_vlan_interface()

    def on_router_eap(self, eap):
        args = self.args
        if not args.set_mac:
            return

        if_vlan = args.if_wan + ".0"
        if self.os.getmac(if_vlan) == eap.src:
            return

        self.log("%s: setting mac to %s", if_vlan, strmac(eap.src))
        self.os.setmac(if_vlan, eap.src)

    def on_wan_eap(self, eap):
        args = self.args
        if not args.restart_dhcp:
            return
        if not eap.is_success:
            return
        if self.check_vlan_interface():
            return

        if_vlan = args.if_wan + ".0"
        self.log("%s: restarting dhclient", if_vlan)
        self.os.restart_dhclient(if_vlan)

    def check_vlan_interface(self):
        args = self.args
        if args.ignore_wan_has_ip:
            # just check for an ip
            check_interface = if_addr
        elif args.ignore_wan_ping_gateway:
            # check for an ip, then try to ping the default gateway
            def check_interface(name):
                addr = if_addr(name)
                if addr and self.os.check_interface(name):
                    return addr
        else:
            return False

        if_vlan = args.if_wan + ".0"
        if time.time() - self.last_check_vlan_if_time >= CHECK_VLAN_IF_TTL:
            cached, result = False, check_interface(if_vlan)
            self.last_check_vlan_if_result = result
            self.last_check_vlan_if_time = time.time()
        else:
            cached, result = True, self.last_check_vlan_if_result

        self.log(
            "%s: check interface %s%s", if_vlan,
            "success [%s]" % result if result else "failure",
            " (cached)" if cached else '')

        return result


### Main

def parse_args():
    p = argparse.ArgumentParser("eap_proxy")

    # interface arguments
    p.add_argument(
        "if_wan", metavar="IF_WAN", help="interface of the AT&T ONT/WAN")
    p.add_argument(
        "if_rtr", metavar="IF_ROUTER", help="interface of the AT&T router")

    # ignoring packet options
    g = p.add_argument_group("ignoring router packets")
    g.add_argument(
        "--ignore-wan-has-ip", action="store_true", help=
        "ignore router packets if IF_WAN.0 has an IP address assigned")
    g.add_argument(
        "--ignore-wan-ping-gateway", action="store_true", help=
        "ignore router packets if IF_WAN.0 has a reachable default gateway")
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
        "restart IF_WAN.0 dhclient after receiving EAP-Success "
        "if IF_WAN.0 does not have a reachable default gateway")
    g.add_argument(
        "--set-mac", action="store_true", help=
        "set IF_WAN.0 MAC to router's MAC")

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
        "--debug-packets", action="store_true", help=
        "print packets in hex format to assist with debugging")

    args = p.parse_args()
    if args.daemon:
        args.syslog = True
    return args


def main():
    args = parse_args()
    log = make_logger(args.syslog)

    if args.pidfile:
        pid = checkpidfile(args.pidfile)
        if pid:
            log.error("eap_proxy already running with pid %s?", pid)
            return 1

    if args.daemon:
        daemonize()

    if args.pidfile:
        try:
            writepidfile(args.pidfile, log)
        except Exception as ex:  # pylint:disable=broad-except
            log.error("could not write pidfile: %s", ex, exc_info=ex)

    EAPProxy(args, log).proxy_forever()


if __name__ == "__main__":
    sys.exit(main())
