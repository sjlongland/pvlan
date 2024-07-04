#!/usr/bin/env python3

"""
Ethernet frame encoding/decoding
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import enum
from .mac import MAC


class EthertypeMixin(object):
    """
    Mix-in class to define the ethertype interface
    """

    def __bytes__(self):
        """
        Encode the EtherType as big-endian bytes
        """
        proto = int(self) & 0xFFFF
        return bytes([proto >> 8, proto & 0x00FF])


class UnknownEthertype(EthertypeMixin):
    """
    Placeholder Ethertype for ethernet types not defined in the Ethertype
    enumeration.
    """

    def __init__(self, proto):
        self._proto = int(proto)

    @property
    def value(self):
        """
        Return the Ethertype protocol number. For compatibility with Enum.
        """
        return self._proto

    @property
    def label(self):
        """
        Return the label for the Ethertype protocol. For compatibility with
        Enum.
        """
        return "%s(0x%04X)" % (self.__class__.__name__, self.value)

    def __repr__(self):
        """
        Return a representation of the unknown value, for compatibility with
        Enum.
        """
        return "<%s: %d>" % (self.label, self.value)

    def __str__(self):
        """
        Return the label for the enumeration, for compatibility with Enum.
        """
        return self.label

    def __int__(self):
        """
        Return the enumeration value.
        """
        return self.value


class Ethertype(EthertypeMixin, enum.Enum):
    """
    Ethertypes, as defined by Linux kernel ``linux/if_ether.h``.

    Authors:
    - Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
    - Donald Becker, <becker@super.org>
    - Alan Cox, <alan@lxorguk.ukuu.org.uk>
    - Steve Whitehouse, <gw7rrm@eeshack3.swan.ac.uk>
    et all.

    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_ether.h
    """

    @classmethod
    def lookup(cls, proto):
        """
        Look-up an existing Ethertype, or create an UnknownEthertype to record
        it.
        """
        try:
            return cls(proto)
        except ValueError:
            # Not a recognised ethertype!
            pass

        return UnknownEthertype(proto)

    @classmethod
    def decode(cls, protobytes):
        """
        Decode a big-endian Ethertype field.
        """
        if isinstance(protobytes, (Ethertype, UnknownEthertype)):
            # Nothing to do
            return protobytes

        return cls.lookup((protobytes[0] << 8) | protobytes[1])

    # Ethernet Loopback packet
    ETH_P_LOOP = 0x0060
    # Xerox PUP packet
    ETH_P_PUP = 0x0200
    # Xerox PUP Addr Trans packet
    ETH_P_PUPAT = 0x0201
    # TSN (IEEE 1722) packet
    ETH_P_TSN = 0x22F0
    # ERSPAN version 2 (type III)
    ETH_P_ERSPAN2 = 0x22EB
    # Internet Protocol packet
    ETH_P_IP = 0x0800
    # CCITT X.25
    ETH_P_X25 = 0x0805
    # Address Resolution packet
    ETH_P_ARP = 0x0806
    # G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_BPQ = 0x08FF
    # Xerox IEEE802.3 PUP packet
    ETH_P_IEEEPUP = 0x0A00
    # Xerox IEEE802.3 PUP Addr Trans packet
    ETH_P_IEEEPUPAT = 0x0A01
    # B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_BATMAN = 0x4305
    # DEC Assigned proto
    ETH_P_DEC = 0x6000
    # DEC DNA Dump/Load
    ETH_P_DNA_DL = 0x6001
    # DEC DNA Remote Console
    ETH_P_DNA_RC = 0x6002
    # DEC DNA Routing
    ETH_P_DNA_RT = 0x6003
    # DEC LAT
    ETH_P_LAT = 0x6004
    # DEC Diagnostics
    ETH_P_DIAG = 0x6005
    # DEC Customer use
    ETH_P_CUST = 0x6006
    # DEC Systems Comms Arch
    ETH_P_SCA = 0x6007
    # Trans Ether Bridging
    ETH_P_TEB = 0x6558
    # Reverse Addr Res packet
    ETH_P_RARP = 0x8035
    # Appletalk DDP
    ETH_P_ATALK = 0x809B
    # Appletalk AARP
    ETH_P_AARP = 0x80F3
    # 802.1Q VLAN Extended Header
    ETH_P_8021Q = 0x8100
    # ERSPAN type II
    ETH_P_ERSPAN = 0x88BE
    # IPX over DIX
    ETH_P_IPX = 0x8137
    # IPv6 over bluebook
    ETH_P_IPV6 = 0x86DD
    # IEEE Pause frames. See 802.3 31B
    ETH_P_PAUSE = 0x8808
    # Slow Protocol. See 802.3ad 43B
    ETH_P_SLOW = 0x8809
    # Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
    ETH_P_WCCP = 0x883E
    # MPLS Unicast traffic
    ETH_P_MPLS_UC = 0x8847
    # MPLS Multicast traffic
    ETH_P_MPLS_MC = 0x8848
    # MultiProtocol Over ATM
    ETH_P_ATMMPOA = 0x884C
    # PPPoE discovery messages
    ETH_P_PPP_DISC = 0x8863
    # PPPoE session messages
    ETH_P_PPP_SES = 0x8864
    # HPNA, wlan link local tunnel
    ETH_P_LINK_CTL = 0x886C
    # Frame-based ATM Transport over Ethernet
    ETH_P_ATMFATE = 0x8884
    # Port Access Entity (IEEE 802.1X)
    ETH_P_PAE = 0x888E
    # PROFINET
    ETH_P_PROFINET = 0x8892
    # Multiple proprietary protocols
    ETH_P_REALTEK = 0x8899
    # ATA over Ethernet
    ETH_P_AOE = 0x88A2
    # EtherCAT
    ETH_P_ETHERCAT = 0x88A4
    # 802.1ad Service VLAN
    ETH_P_8021AD = 0x88A8
    # 802.1 Local Experimental 1.
    ETH_P_802_EX1 = 0x88B5
    # 802.11 Preauthentication
    ETH_P_PREAUTH = 0x88C7
    # TIPC
    ETH_P_TIPC = 0x88CA
    # Link Layer Discovery Protocol
    ETH_P_LLDP = 0x88CC
    # Media Redundancy Protocol
    ETH_P_MRP = 0x88E3
    # 802.1ae MACsec
    ETH_P_MACSEC = 0x88E5
    # 802.1ah Backbone Service Tag
    ETH_P_8021AH = 0x88E7
    # 802.1Q MVRP
    ETH_P_MVRP = 0x88F5
    # IEEE 1588 Timesync
    ETH_P_1588 = 0x88F7
    # NCSI protocol
    ETH_P_NCSI = 0x88F8
    # IEC 62439-3 PRP/HSRv0
    ETH_P_PRP = 0x88FB
    # Connectivity Fault Management
    ETH_P_CFM = 0x8902
    # Fibre Channel over Ethernet
    ETH_P_FCOE = 0x8906
    # Infiniband over Ethernet
    ETH_P_IBOE = 0x8915
    # TDLS
    ETH_P_TDLS = 0x890D
    # FCoE Initialization Protocol
    ETH_P_FIP = 0x8914
    # IEEE 802.21 Media Independent Handover Protocol
    ETH_P_80221 = 0x8917
    # IEC 62439-3 HSRv1
    ETH_P_HSR = 0x892F
    # Network Service Header
    ETH_P_NSH = 0x894F
    # Ethernet loopback packet, per IEEE 802.3
    ETH_P_LOOPBACK = 0x9000
    # deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_QINQ1 = 0x9100
    # deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_QINQ2 = 0x9200
    # deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_QINQ3 = 0x9300
    # Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_EDSA = 0xDADA
    # Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_DSA_8021Q = 0xDADB
    # A5PSW Tag Value [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_DSA_A5PSW = 0xE001
    # ForCES inter-FE LFB type
    ETH_P_IFE = 0xED3E
    # IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_AF_IUCV = 0xFBFB

    # If the value in the ethernet type is more than this value
    # then the frame is Ethernet II. Else it is 802.3
    ETH_P_802_3_MIN = 0x0600

    # Non DIX types. Won't clash for 1500 types.

    # Dummy type for 802.3 frames
    ETH_P_802_3 = 0x0001
    # Dummy protocol id for AX.25
    ETH_P_AX25 = 0x0002
    # Every packet (be careful!!!)
    ETH_P_ALL = 0x0003
    # 802.2 frames
    ETH_P_802_2 = 0x0004
    # Internal only
    ETH_P_SNAP = 0x0005
    # DEC DDCMP: Internal only
    ETH_P_DDCMP = 0x0006
    # Dummy type for WAN PPP frames*/
    ETH_P_WAN_PPP = 0x0007
    # Dummy type for PPP MP frames
    ETH_P_PPP_MP = 0x0008
    # Localtalk pseudo type
    ETH_P_LOCALTALK = 0x0009
    # CAN: Controller Area Network
    ETH_P_CAN = 0x000C
    # CANFD: CAN flexible data rate*/
    ETH_P_CANFD = 0x000D
    # CANXL: eXtended frame Length
    ETH_P_CANXL = 0x000E
    # Dummy type for Atalk over PPP*/
    ETH_P_PPPTALK = 0x0010
    # 802.2 frames
    ETH_P_TR_802_2 = 0x0011
    # Mobitex (kaz@cafe.net)
    ETH_P_MOBITEX = 0x0015
    # Card specific control frames
    ETH_P_CONTROL = 0x0016
    # Linux-IrDA
    ETH_P_IRDA = 0x0017
    # Acorn Econet
    ETH_P_ECONET = 0x0018
    # HDLC frames
    ETH_P_HDLC = 0x0019
    # 1A for ArcNet :-)
    ETH_P_ARCNET = 0x001A
    # Distributed Switch Arch.
    ETH_P_DSA = 0x001B
    # Trailer switch tagging
    ETH_P_TRAILER = 0x001C
    # Nokia Phonet frames
    ETH_P_PHONET = 0x00F5
    # IEEE802.15.4 frame
    ETH_P_IEEE802154 = 0x00F6
    # ST-Ericsson CAIF protocol
    ETH_P_CAIF = 0x00F7
    # Multiplexed DSA protocol
    ETH_P_XDSA = 0x00F8
    # Qualcomm multiplexing and aggregation protocol
    ETH_P_MAP = 0x00F9

    # Management component transport protocol packets
    ETH_P_MCTP = 0x00FA

    def __int__(self):
        """
        Cast the Ethertype value to an integer.
        """
        return self.value


class EthernetPayload(object):
    """
    EthernetPayload is a base class that stores the Ethertype header field
    along with the payload data for the frame.  This is used in particular
    with IEEE 802.1Q, which whilst normally not nested in practice, can be
    nested up to the MTU limits of the underlying link.

    The base class is used to represent all generic protocols, with a specific
    sub-class for handling VLANs.
    """

    @staticmethod
    def decode(framedata):
        proto = Ethertype.decode(framedata[0:2])

        if proto == Ethertype.ETH_P_8021Q:
            # IEEE 802.1Q, skip the ethertype check as we've done that already
            # just here.
            return VLANEthernetPayload.decode(
                framedata, check_ethertype=False
            )
        elif proto == Ethertype.ETH_P_ARP:
            return ARPEthernetPayload.decode(framedata, check_ethertype=False)
        elif proto == Ethertype.ETH_P_IP:
            return IPv4EthernetPayload.decode(
                framedata, check_ethertype=False
            )
        elif proto == Ethertype.ETH_P_IPV6:
            return IPv6EthernetPayload.decode(
                framedata, check_ethertype=False
            )
        else:
            # Not a known Ethertype, so just use the base class
            return EthernetPayload(proto, framedata[2:])

    def __init__(self, proto, payload):
        self._proto = Ethertype.decode(proto)
        self._payload = payload

    @property
    def proto(self):
        """
        Return the Ethertype protocol number.
        """
        return self._proto

    @property
    def payload(self):
        """
        Return the frame payload
        """
        return self._payload

    def __bytes__(self):
        """
        Return the complete EtherType-tagged frame.
        """
        return bytes(self.proto) + bytes(self.payload)

    def __repr__(self):
        """
        Return a representation of the payload.
        """
        payload = self.payload
        if isinstance(payload, bytes):
            payload = "bytes.fromhex(%r)" % payload.hex()

        return "<%s: proto=%s payload=%s>" % (
            self.__class__.__name__,
            self.proto,
            payload,
        )


class UndecodedEthernetPayload(EthernetPayload):
    """
    Representation of a payload we're not decoding
    """

    @classmethod
    def decode(cls, rawframe, check_ethertype=True):
        if check_ethertype:
            proto = Ethertype.decode(rawframe[0:2])
            if proto != cls.ETHERTYPE:
                raise ValueError(
                    "Expected ethertype to be %s, got %s"
                    % (cls.ETHERTYPE, proto)
                )

        return cls(rawframe[2:])

    def __init__(self, payload):
        super().__init__(
            proto=self.ETHERTYPE,
            payload=payload,
        )

    def __repr__(self):
        """
        Return a representation of the payload.
        """
        # We drop out the protocol number, since we can infer this
        # from the class name.
        return "<%s: payload=bytes.fromhex(%r)>" % (
            self.__class__.__name__,
            bytes(self.payload).hex(),
        )


class ARPEthernetPayload(UndecodedEthernetPayload):
    """
    Representation of an ARP packet
    """

    ETHERTYPE = Ethertype.ETH_P_ARP


class IPv4EthernetPayload(UndecodedEthernetPayload):
    """
    Representation of an IPv4 packet
    """

    ETHERTYPE = Ethertype.ETH_P_IP


class IPv6EthernetPayload(UndecodedEthernetPayload):
    """
    Representation of an IPv6 packet
    """

    ETHERTYPE = Ethertype.ETH_P_IPV6


class VLANEthernetPayload(EthernetPayload):
    """
    Representation of an IEEE 802.1Q tagged Ethernet payload.
    """

    VLAN_MASK = 0x00FFFFFF
    VLAN_PRI = 0xE0000000
    VLAN_PRI_POS = 13
    VLAN_DEI = 0x10000000

    @classmethod
    def decode(cls, rawframe, check_ethertype=True):
        if check_ethertype:
            proto = Ethertype.decode(rawframe[0:2])
            if proto != Ethertype.ETH_P_8021Q:
                raise ValueError("Not a IEEE 802.1Q payload")

        # Unpack the VLAN tag:
        # - 3 bits:  Priority
        # - 1 bit:   Drop eligible indicator
        # - 12 bits: VLAN ID
        tagvalue = (rawframe[2] << 8) | rawframe[3]

        return cls(
            priority=(tagvalue & cls.VLAN_PRI) >> cls.VLAN_PRI_POS,
            dei=bool(tagvalue & cls.VLAN_DEI),
            vlan_id=tagvalue & cls.VLAN_MASK,
            # Decode the inner payload, in case it's a nested VLAN tag
            payload=EthernetPayload.decode(rawframe[4:]),
        )

    def __init__(self, vlan_id, payload, dei=False, priority=0):
        super().__init__(
            proto=Ethertype.ETH_P_8021Q,
            payload=payload,
        )
        self._vlan_id = vlan_id & self.VLAN_MASK
        self._dei = bool(dei)
        self._priority = int(priority)

    @property
    def vlan_id(self):
        return self._vlan_id

    @property
    def dei(self):
        return self._dei

    @property
    def priority(self):
        return self._priority

    @property
    def vlan_tag(self):
        """
        Return the bytes for encoding the VLAN tag field.
        """
        tagvalue = (
            ((self.priority << self.VLAN_PRI_POS) & self.VLAN_PRI)
            | (self.VLAN_DEI if self.dei else 0)
            | (self.vlan_id & self.VLAN_MASK)
        )

        return bytes([(tagvalue & 0xFF00) >> 8, tagvalue & 0x00FF])

    def __bytes__(self):
        """
        Return the complete Ethernet payload with Ethertype
        fields and VLAN tag.
        """
        return (
            # Ethertype and VLAN tag for IEEE 802.1Q
            bytes(self.proto)
            + self.vlan_tag
            # Payload with its Ethertype
            + bytes(self.payload)
        )


class EthernetFrame(object):
    """
    Representation of a raw Ethernet frame.
    """

    @staticmethod
    def decode(framedata):
        return EthernetFrame(
            dest_mac=MAC.parse(framedata[0:6]),
            src_mac=MAC.parse(framedata[6:12]),
            payload=EthernetPayload.decode(framedata[12:]),
        )

    def __init__(self, dest_mac, src_mac, payload):
        self._dest_mac = MAC.parse(dest_mac)
        self._src_mac = MAC.parse(src_mac)
        self._payload = payload

    @property
    def dest_mac(self):
        """
        Return the destination MAC address for the frame.
        """
        return self._dest_mac

    @property
    def src_mac(self):
        """
        Return the source MAC address for the frame.
        """
        return self._src_mac

    @property
    def payload(self):
        """
        Return the ethernet frame payload
        """
        return self._payload

    def __bytes__(self):
        """
        Return the complete Ethernet frame with MAC addresses and Ethertype
        fields.
        """
        return (
            bytes(self.dest_mac) + bytes(self.src_mac) + bytes(self.payload)
        )

    def __repr__(self):
        """
        Return a representation of the frame.
        """
        return "<%s: dest_mac=%r, src_mac=%r, payload=%r>" % (
            self.__class__.__name__,
            self.dest_mac,
            self.src_mac,
            self.payload,
        )

    @property
    def is_vlan(self):
        """
        Return true if this frame is 802.1Q VLAN tagged.
        """
        return self.payload.proto == Ethertype.ETH_P_8021Q

    def to_vlan(self, vlan_id, priority=0, dei=False, nest=False):
        """
        Generate a frame that sends this traffic via a specific VLAN.
        This creates or re-writes the outer-most VLAN tag to route this
        frame to the nominated VLAN.
        """
        payload = self.payload

        if self.is_vlan:
            # We already have a tagged frame
            if not nest:
                # Strip the VLAN layer
                payload = payload.payload

        # Wrap this in a new VLAN payload
        payload = VLANEthernetPayload(
            priority=priority,
            dei=dei,
            vlan_id=vlan_id,
            payload=payload,
        )

        # Construct a new frame around the payload
        return EthernetFrame(
            dest_mac=self.dest_mac, src_mac=self.src_mac, payload=payload
        )

    def drop_vlan(self):
        """
        Drop the outermost VLAN layer.  Returns the same frame if the frame
        is not VLAN-tagged.
        """
        if not self.is_vlan:
            # Nothing to do
            return self

        # Construct a new frame around the payload
        return EthernetFrame(
            dest_mac=self.dest_mac,
            src_mac=self.src_mac,
            payload=self.payload.payload,
        )
