#!/usr/bin/env python3

"""
MAC Address routines.  This module provides code that can generate randomised
MAC addresses and MAC OUIs to ensure each node has a controlled unique
address.
"""
# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import re
import weakref

# Regex for OUIs
OUI_RE = re.compile(
    pattern=(r"^([0-9a-f]{2})([^0-9a-f])([0-9a-f]{2})\2([0-9a-f]{2})$"),
    flags=re.IGNORECASE,
)


# Regex for MACs
MAC_RE = re.compile(
    pattern=(
        r"^([0-9a-f]{2})([^0-9a-f])"
        r"([0-9a-f]{2})\2"
        r"([0-9a-f]{2})\2"
        r"([0-9a-f]{2})\2"
        r"([0-9a-f]{2})\2"
        r"([0-9a-f]{2})$"
    ),
    flags=re.IGNORECASE,
)


# Mask representing no OUI bits selected
OUI_MASK_NONE = 0x000000

# Mask representing all OUI bits selected
OUI_MASK_ALL = 0xFCFFFF

# OUI bit position within a MAC address
OUI_POS = 24

# Mask representing the OUI bits has been allocated by the IEEE and thus is
# globally unique.
OUI_MASK_GLOBAL = 0x020000

# Mask representing a multicast MAC address
OUI_MASK_MCAST = 0x010000

# MAC Node address all zeroes
NODEADDR_MASK_NONE = 0x000000

# MAC Node address mask
NODEADDR_MASK_ALL = 0xFFFFFF

# MAC full address all zeroes
MAC_MASK_NONE = 0x000000000000

# MAC full address, all un-reserved bits set
MAC_MASK_ALL = (OUI_MASK_ALL << OUI_POS) | NODEADDR_MASK_ALL


# OUI registry, all instances of OUIs are kept here
_OUI = weakref.WeakValueDictionary()


def _int_to_bytes(intval, length):
    """
    Convert an integer to a byte string (big-endian)
    """
    ba = bytearray(length)
    for p in range(length):
        # Encode as big-endian
        ba[length - p - 1] = (intval >> (p * 8)) & 0xFF

    return bytes(ba)


def _bytes_to_int(byteval):
    """
    Convert an byte string (big-endian) to an integer
    """
    out = 0
    for v in byteval:
        out <<= 8
        out |= v

    return out


def _randint(length):
    """
    Return a random N-byte integer.
    """
    return _bytes_to_int(os.urandom(length))


def _randint_mask(fixed, mask, length):
    """
    Return a random N-byte integer whose bits are masked.
    """
    all_bits = (1 << (length * 8)) - 1
    fixed &= all_bits
    mask &= all_bits

    # Are there any random bits?
    if ~mask & all_bits:
        # Generate a random integer of the required length
        out = _randint(length)

        # Mask out bits expected to be fixed
        out &= ~mask
    else:
        # Start with zeroes
        out = 0

    # Add in fixed bits
    out |= fixed

    # Return the semi-random integer
    return out


class MAC(object):
    """
    Representation of a MAC address.
    """

    # Length of a node address
    NODEADDR_LEN = 3

    # MAC for broadcast traffic (byte representation)
    BROADCAST_NODEADDR_BYTES = bytes((0xFF, 0xFF, 0xFF))

    @classmethod
    def parse(cls, mac, reserve=False, register=True):
        """
        Parse a MAC from a text or byte string.
        """
        if isinstance(mac, str):
            # str → bytes
            mac = cls.decodestr(mac)

        elif not isinstance(mac, cls):
            # bytes → int
            mac = cls.fromint(
                cls.decodebytes(mac), reserve=reserve, register=register
            )

        return mac

    @classmethod
    def fromcfg(cls, **mac_cfg):
        """
        Generate a MAC from a pre-defined configuration.
        """
        for field in ("fixed", "mask"):
            if field in mac_cfg:
                field[mac_cfg] = cls.parse(field[mac_cfg])

        return cls.generate_mac(**mac_cfg)

    @staticmethod
    def decodestr(strmac):
        """
        Decode a MAC from a string representation into raw bytes
        """
        # Extract the MAC bytes
        match = MAC_RE.match(strmac)
        if not match:
            raise ValueError("%r is not a valid MAC" % strmac)

        (o1, _, o2, o3, n1, n2, n3) = match.groups()
        return bytes.fromhex(o1 + o2 + o3 + n1 + n2 + n3)

    @staticmethod
    def decodebytes(bytesmac):
        """
        Decode a MAC in byte representation into an integer.
        """
        return (
            (bytesmac[0] << 40)
            | (bytesmac[1] << 32)
            | (bytesmac[2] << 24)
            | (bytesmac[3] << 16)
            | (bytesmac[4] << 8)
            | bytesmac[5]
        )

    @classmethod
    def fromstr(cls, strmac, reserve=False, register=True):
        """
        Construct a MAC from a string.
        """
        return cls.frombytes(
            cls.decodestr(strmac), reserve=reserve, register=register
        )

    @classmethod
    def frombytes(cls, bytesmac, reserve=False, register=True):
        """
        Construct a MAC from a byte string.
        """
        return cls.fromint(
            cls.decodebytes(bytesmac), reserve=reserve, register=register
        )

    @classmethod
    def fromint(cls, intmac, reserve=False, register=True):
        """
        Construct a MAC from an integer.
        """
        # Peel off the OUI
        intoui = intmac >> OUI_POS
        intmac &= NODEADDR_MASK_ALL

        # Fetch the OUI
        oui = MACOUI.fromint(intoui, register=register)

        # Retrieve the MAC
        mac = oui.getaddr(intmac)
        if reserve:
            mac.reserve()

        return mac

    @classmethod
    def generate_mac(
        cls,
        fixed=MAC_MASK_NONE,
        mask=MAC_MASK_NONE,
        is_global=False,
        is_multicast=False,
        reserve=True,
        register=True,
    ):
        """
        Generate a randomised MAC address with fixed bits decided by the
        fixed bits given in `fixed` and `mask`.
        """
        # Retrieve the OUI
        oui = MACOUI.generate_oui(
            fixed=fixed >> OUI_POS,
            mask=mask >> OUI_POS,
            is_global=is_global,
            is_multicast=is_multicast,
            register=register,
            mac_class=cls,
        )

        # Generate a MAC within this OUI
        return oui.generate_mac(
            fixed=fixed & NODEADDR_MASK_ALL,
            mask=mask & NODEADDR_MASK_ALL,
            reserve=reserve,
        )

    def __init__(self, oui, nodeaddr):
        """
        Construct a new MAC from the given OUI and 24-bit node address.
        """
        self._oui = oui
        self._nodeaddr = nodeaddr
        self._nodebytes = _int_to_bytes(nodeaddr, self.NODEADDR_LEN)

    @property
    def oui(self):
        """
        Return the OUI for this MAC
        """
        return self._oui

    @property
    def is_global(self):
        """
        Return the global bit.  If set, this means the MAC is one of a range
        officially allocated by the IEEE.
        """
        return self.oui.is_global

    @property
    def is_multicast(self):
        """
        Return the multicast bit.  If set, this means the MAC represents a
        multicast group.
        """
        return self.oui.is_multicast

    @property
    def is_broadcast(self):
        """
        Return true if this is the broadcast OUI (FF:FF:FF).
        """
        return self.oui.is_broadcast and (
            self._nodebytes == self.BROADCAST_NODEADDR_BYTES
        )

    @property
    def nodeaddr(self):
        """
        Return the node address for this MAC
        """
        return self._nodeaddr

    def __eq__(self, other):
        """
        Determine if this is the same MAC as another.
        """
        if not isinstance(other, MAC):
            return NotImplemented

        return bytes(self) == bytes(other)

    def __int__(self):
        """
        Return the complete encoded EUI-48 for this MAC address as an integer.
        """
        return (int(self._oui) << (8 * MACOUI.OUI_LEN)) | self._nodeaddr

    def __bytes__(self):
        """
        Return the complete encoded EUI-48 for this MAC address.
        """
        return bytes(self._oui) + self._nodebytes

    def __str__(self):
        """
        Return the complete EUI-48 in canonical form.
        """
        return bytes(self).hex(":")

    def __repr__(self):
        """
        Return a string representation of the address.
        """
        return "%s.fromstr(%r)" % (self.__class__.__name__, str(self))

    def __hash__(self):
        """
        Return a hash value for the MAC address
        """
        return hash(int(self))

    @property
    def is_reserved(self):
        """
        Return true if the MAC address is reserved.
        """
        return self.oui.is_reserved(self.nodeaddr)

    def reserve(self):
        """
        Mark this MAC address as reserved.
        """
        self.oui.reserve(self.nodeaddr)

    def unreserve(self):
        """
        Mark this MAC address as reserved.
        """
        self.oui.unreserve(self.nodeaddr)


class MACOUI(object):
    """
    OUI component of the MAC address.  This provides a means to either
    configure a fixed OUI for all the nodes under the control of a single
    operator/vendor, or a (semi)randomly generated OUI with a configurable
    mask to select which bits are random.
    """

    # Length of an OUI in bytes
    OUI_LEN = 3

    # OUI for broadcast traffic (byte representation)
    BROADCAST_OUI_BYTES = bytes((0xFF, 0xFF, 0xFF))

    @staticmethod
    def decodestr(stroui):
        """
        Decode a OUI from a string representation into raw bytes
        """
        # Extract the OUI bytes
        match = OUI_RE.match(stroui)
        if not match:
            raise ValueError("%r is not a valid OUI" % stroui)

        (b1, _, b2, b3) = match.groups()
        return bytes.fromhex(b1 + b2 + b3)

    @staticmethod
    def decodebytes(bytesoui):
        """
        Decode a OUI in byte representation into an integer.
        """
        return (bytesoui[0] << 24) | (bytesoui[1] << 16) | bytesoui[2]

    @classmethod
    def fromstr(cls, stroui, register=True):
        """
        Decode a OUI from a string representation.
        """
        return cls.frombytes(cls.decodestr(stroui), register=register)

    @classmethod
    def frombytes(cls, bytesoui, register=True):
        """
        Decode a OUI from raw bytes.
        """
        return cls.fromint(cls.decodebytes(bytesoui), register=register)

    @classmethod
    def fromint(cls, intoui, register=True):
        """
        Decode a OUI from integer representation, or return an existing
        matching OUI from the registry.
        """
        try:
            return _OUI[intoui]
        except KeyError:
            pass

        # Return the decoded OUI
        oui = cls(intoui=intoui)

        if register:
            oui.register()
        return oui

    @classmethod
    def generate_oui(
        cls,
        fixed=OUI_MASK_NONE,
        mask=OUI_MASK_NONE,
        is_global=False,
        is_multicast=False,
        register=True,
        mac_class=MAC,
    ):
        intoui = _randint_mask(
            fixed=fixed & OUI_MASK_ALL,
            mask=mask & OUI_MASK_ALL,
            length=cls.OUI_LEN,
        )

        # Set the global/multicast bits if requested

        if is_global:
            intoui |= OUI_MASK_GLOBAL

        if is_multicast:
            intoui |= OUI_MASK_MCAST

        oui = cls(intoui=intoui, mac_class=mac_class)
        if register:
            oui.register()
        return oui

    def __init__(
        self,
        intoui,
        mac_class=MAC,
    ):
        # Store the encoded OUI and parameters
        self._oui = intoui
        self._ouibytes = _int_to_bytes(intoui, self.OUI_LEN)
        self._is_global = bool(intoui & OUI_MASK_GLOBAL)
        self._is_multicast = bool(intoui & OUI_MASK_MCAST)

        # Class used for MAC instances
        self._mac_class = mac_class

        # MAC addresses registered with this OUI
        self._mac = weakref.WeakValueDictionary()

        # Reserved MACs
        self._reserved = set()

    @property
    def is_global(self):
        """
        Return the global bit.  If set, this means the OUI is one of a range
        officially allocated by the IEEE.
        """
        return self._is_global

    @property
    def is_multicast(self):
        """
        Return the multicast bit.  If set, this means the OUI represents a
        multicast group.
        """
        return self._is_multicast

    @property
    def is_broadcast(self):
        """
        Return true if this is the broadcast OUI (FF:FF:FF).
        """
        return self._ouibytes == self.BROADCAST_OUI_BYTES

    def __eq__(self, other):
        """
        Determine if this is the same OUI as another.
        """
        if not isinstance(other, MACOUI):
            return NotImplemented

        return bytes(self) == bytes(other)

    def __bytes__(self):
        """
        Return the OUI bytes.
        """
        return self._ouibytes

    def __str__(self):
        """
        Return the OUI in human-readable form.
        """
        return self._ouibytes.hex(":")

    def __repr__(self):
        return "%s.fromstr(%r)" % (self.__class__.__name__, str(self))

    def register(self):
        """
        Register this OUI in the registry.
        """
        if self._oui in _OUI:
            raise ValueError("Duplicate OUI %s" % self)

        _OUI[self._oui] = self

    def getaddr(self, nodeaddr):
        """
        Retrieve a MAC address corresponding to the given node address.
        """
        nodeaddr &= NODEADDR_MASK_ALL

        try:
            return self._mac[nodeaddr]
        except KeyError:
            pass

        # Create a new one
        mac = self._mac_class(self, nodeaddr)
        self._mac[nodeaddr] = mac
        return mac

    def reserve(self, nodeaddr):
        """
        Reserve a node address.
        """
        nodeaddr &= NODEADDR_MASK_ALL
        self._reserved.add(nodeaddr)

    def unreserve(self, nodeaddr):
        """
        Unreserve a node address.
        """
        nodeaddr &= NODEADDR_MASK_ALL
        self._reserved.discard(nodeaddr)

    def is_reserved(self, nodeaddr):
        """
        Determine if a node address is already reserved.
        """
        nodeaddr &= NODEADDR_MASK_ALL
        return nodeaddr in self._reserved

    def is_in_use(self, nodeaddr):
        """
        Determine if a node address is already in use.
        """
        nodeaddr &= NODEADDR_MASK_ALL
        return nodeaddr in self._mac

    def is_available(self, nodeaddr):
        """
        Determine if a node address is available for use.
        """
        return (not self.is_reserved(nodeaddr)) and (
            not self.is_in_use(nodeaddr)
        )

    def generate_mac(
        self, fixed=NODEADDR_MASK_NONE, mask=NODEADDR_MASK_NONE, reserve=True
    ):
        """
        Generate a MAC, and optionally reserve it.
        """
        # NOTE: not thread safe!
        nodeaddr = _randint_mask(
            fixed=fixed, mask=mask, length=self._mac_class.NODEADDR_LEN
        )
        while not self.is_available(nodeaddr):
            # Taken, roll the dice again!
            nodeaddr = _randint_mask(
                fixed=fixed, mask=mask, length=self._mac_class.NODEADDR_LEN
            )

        mac = self.getaddr(nodeaddr)
        if reserve:
            mac.reserve()

        return mac
