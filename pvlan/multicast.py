#!/usr/bin/env python3

"""
Very simple multicast IPv6 socket implementation in asyncio.

Allows for transmission and reception of UDPv6 datagrams to and from multicast
groups.
"""

# © 2024       Stuart Longland <me@vk4msl.com>
# © 2014-2024  Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

# Credit: aiocoap
# https://github.com/chrysn/aiocoap/blob/7715695a2a4db3dc3853145e1ffed2f786094658/aiocoap/transports/udp6.py

import asyncio
import socket
import struct
import ipaddress
import logging
import sys

_IPV6_ADDR_ST = struct.Struct("16si")

# Linux and MacOS X setsockopt numbers are from aiocoap too!
# OpenBSD numbers found by grepping /usr/include for IPV6_RECVPKTINFO.
# https://github.com/chrysn/aiocoap/blob/7715695a2a4db3dc3853145e1ffed2f786094658/aiocoap/util/socknumbers.py
try:
    IPV6_RECVPKTINFO = socket.IPV6_RECVPKTINFO
except AttributeError:
    if sys.platform == "linux":
        IPV6_RECVPKTINFO = 49
    elif sys.platform.startswith("openbsd"):  # e.g. openbsd7
        IPV6_RECVPKTINFO = 36
    elif sys.platform == "darwin":
        IPV6_RECVPKTINFO = 61
    else:
        # Send a patch!
        raise


class MulticastIPv6Socket(object):
    @staticmethod
    def _scope_if_idx(scope_id):
        """
        Retrieve the IF index of the address given.
        """
        # Assume a raw interface number
        try:
            return int(scope_id)
        except ValueError:
            pass

        # Try an interface name
        return socket.if_nametoindex(scope_id)

    @classmethod
    def _encode_addr(cls, a):
        """
        Encode an IPv6 address.
        """
        a = ipaddress.IPv6Address(a)
        return _IPV6_ADDR_ST.pack(a.packed, cls._scope_if_idx(a.scope_id))

    def __init__(
        self,
        on_recv,
        port,
        groups=None,
        interfaces=None,
        recv_sz=4096,
        loop=None,
        log=None,
    ):
        if loop is None:
            loop = asyncio.get_event_loop()

        if log is None:
            log = logging.getLogger(
                "%s.%s.%d"
                % (self.__class__.__module__, self.__class__.__name__, port)
            )

        self._on_recv = on_recv
        self._port = port
        self._recv_sz = recv_sz
        self._loop = loop
        self._log = log
        self._groups = set()
        self._interfaces = set()

        self._sock = socket.socket(
            family=socket.AF_INET6, type=socket.SOCK_DGRAM
        )
        self._sock.setblocking(False)
        self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self._sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)

        # Bind to the port, for multicast we _must_ bind to all-zeros address!
        self._sock.bind(("::", port))

        # Begin listening for traffic
        loop.add_reader(self._sock.fileno(), self._on_recv_ready)

        if interfaces is None:
            interfaces = [
                i[1]
                for i in socket.if_nameindex()
                # lo or lo0 is the loopback, TODO there has to be a better
                # way than this!
                if i[1] not in ("lo", "lo0")
            ]

        for ifname in interfaces:
            self.addif(ifname)

        if groups is not None:
            for group in groups:
                self.join(group)

    @property
    def port(self):
        """
        Return the UDP port number in use.
        """
        return self._port

    @property
    def groups(self):
        """
        Return the multicast groups joined.
        """
        return self._groups.copy()

    @property
    def interfaces(self):
        """
        Return the set of interfaces participating.
        """
        return self._interfaces.copy()

    def addif(self, ifname):
        """
        Add an interface to listen for traffic by interface name.
        """
        if ifname in self._interfaces:
            raise KeyError("Duplicate interface %r" % ifname)

        # Join existing groups
        for group in self._groups:
            self._join_iface_group(ifname, group)

        # Wait for traffic
        self._log.debug("Now listening on %s", ifname)
        self._interfaces.add(ifname)

    def rmif(self, ifname):
        """
        Remove an interface.
        """
        self._interfaces.discard(ifname)

        for group in self._groups:
            self._leave_iface_group(ifname, group)

        self._log.debug("Closed socket on %s", ifname)

    def join(self, group):
        """
        Join a multicast group.
        """
        group = ipaddress.IPv6Address(group)
        if group.scope_id is not None:
            raise ValueError("Scope ID may not be given here!")

        for ifname in self._interfaces:
            self._join_iface_group(ifname, group)

        self._groups.add(group)
        if self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(
                "Now listening on groups %s",
                ", ".join(str(g) for g in self._groups),
            )

    def leave(self, group):
        """
        Leave a multicast group.
        """
        group = ipaddress.IPv6Address(group)
        if group.scope_id is not None:
            raise ValueError("Scope ID may not be given here!")

        for ifname in self._interfaces:
            self._leave_iface_group(ifname, group)

        self._groups.discard(group)
        if self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(
                "Now listening on groups %s",
                ", ".join(str(g) for g in self._groups),
            )

    def sendmsg(self, msg, interfaces=None, groups=None):
        """
        Send the given message, optionally to specific interfaces or groups.
        """
        if interfaces is None:
            interfaces = self.interfaces

        if groups is None:
            groups = self.groups

        for ifname in interfaces:
            for group in groups:
                addr = "%s%%%s" % (group, ifname)
                if self._log.isEnabledFor(logging.DEBUG):
                    self._log.debug(
                        "Send to %s port %d: %s", addr, self.port, msg.hex()
                    )
                self._sock.sendto(msg, (addr, self.port))

    def sendmsgto(self, msg, target, *targets, port=None):
        """
        Send the given message to the specified targets.
        """
        if port is None:
            port = self.port

        targets = (target,) + targets

        for target in targets:
            if isinstance(target, tuple):
                # (address, port)
                (addr, tport) = target
            else:
                # address only, port assumed
                addr = target
                tport = port

            addr = ipaddress.IPv6Address(addr)
            if not addr.scope_id:
                raise ValueError("%s has no scope!" % addr)

            if self._log.isEnabledFor(logging.DEBUG):
                self._log.debug(
                    "Send to %s port %d: %s", addr, tport, msg.hex()
                )

            self._sock.sendmsg(msg, (str(addr), tport))

    def _join_iface_group(self, ifname, group):
        self._log.debug("Join %s to group %s", ifname, group)
        self._sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_JOIN_GROUP,
            self._encode_addr("%s%%%s" % (group, ifname)),
        )

    def _leave_iface_group(self, ifname, group):
        self._log.debug("Leave group %s on %s", group, ifname)
        self._sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_LEAVE_GROUP,
            self._encode_addr("%s%%%s" % (group, ifname)),
        )

    def _on_recv_ready(self):
        self._log.debug("Receive ready")
        try:
            (data, (addr, port, flowid, scopeid)) = self._sock.recvfrom(
                self._recv_sz
            )
            ifname = socket.if_indextoname(scopeid)
            self._on_recv(
                ifname=ifname,
                addr=addr,
                port=port,
                data=data,
                flowid=flowid,
                scopeid=scopeid,
            )
        except:
            self._log.exception("Failed to handle incoming data")


if __name__ == "__main__":
    # Quick demo.
    import time

    async def main():
        GROUP_ADDR = "ff02::db8"
        PORT = 65432
        logging.basicConfig(level=logging.DEBUG)
        log = logging.getLogger("multicast")
        listenerlog = log.getChild("listener")

        def _on_rx(ifname, addr, data, **kwargs):
            listenerlog.info("Received on %s from %s: %r", ifname, addr, data)
            listenerlog.debug("Additional data: %r", kwargs)

        mcsock = MulticastIPv6Socket(
            _on_rx, PORT, groups=(GROUP_ADDR,), log=log.getChild("socket")
        )
        while True:
            await asyncio.sleep(10)
            mcsock.sendmsg(("Time is %f" % time.time()).encode())

    asyncio.run(main())
