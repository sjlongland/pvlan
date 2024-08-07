#!/usr/bin/env python3

"""
PVLAN messaging
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import uuid
import time
import enum
from collections.abc import Mapping, Sequence, Set

from pycose.headers import KID
from pycose.messages import (
    CoseMessage,
    Sign1Message,
    Enc0Message,
    Mac0Message,
)

import cbor2

from .key import (
    KeyCertificate,
    KeyID,
    SafeDerivedKey,
    SafeRandomSecret,
    SafeX25519PublicKey,
    import_cose_key,
)
from .mac import MAC
from .frame import VLANEthernetPayload


# Symmetric key lifetime
KEY_LIFETIME = 3600  # 1 hour
KEY_PACKET_COUNT = 100000  # packets

# Approximate ENC0 overhead, measured at ~66 bytes
ENC0_SZ_OVERHEAD = 66

# Approximate SIGN1 overhead, measured at ~99 bytes
SIGN1_SZ_OVERHEAD = 99


class MACSubscription(Sequence):
    """
    Representation of MAC subscription parameters.
    """

    MIN_LIFETIME = 0
    MAX_LIFETIME = 3600

    MIN_COST = 0
    MAX_COST = 65535

    @staticmethod
    def _clamp(value, min_value, max_value):
        return max(min(value, max_value), min_value)

    @classmethod
    def _clamp_lifetime(cls, lifetime):
        return cls._clamp(lifetime, cls.MIN_LIFETIME, cls.MAX_LIFETIME)

    @classmethod
    def _clamp_cost(cls, cost):
        return cls._clamp(cost, cls.MIN_COST, cls.MAX_COST)

    @classmethod
    def _get_lifetime(cls, expiry):
        return int(expiry - time.time())

    def __init__(self, lifetime=None, cost=None, expiry=None):
        # If lifetime is a MACSubscription, clone it.
        if isinstance(lifetime, self.__class__):
            expiry = lifetime.expiry
            cost = lifetime.cost or None
            lifetime = lifetime.lifetime

        # Ensure at least lifetime OR expiry is given
        if lifetime is None:
            # Compute from expiry
            if not isinstance(expiry, int):
                raise ValueError(
                    "expiry must be an integer if lifetime not given"
                )
            lifetime = self._get_lifetime(expiry)

        # Sanitise and clamp inputs
        if not isinstance(lifetime, int):
            raise TypeError("lifetime must be an integer")
        else:
            lifetime = self._clamp_lifetime(lifetime)

        if cost is None:
            cost = self.MIN_COST
        elif not isinstance(cost, int):
            raise TypeError("cost must be an integer")
        else:
            cost = self._clamp_cost(cost)

        # Store the cost as given
        self._cost = cost

        # Compute expiry for local use.  Don't use given expiry as we
        # may have clamped the lifetime.
        if lifetime > 0:
            self._expiry = int(time.time() + lifetime)
        else:
            # Report expiry as 0 since it has passed
            self._expiry = 0

    @property
    def lifetime(self):
        """
        Return the lifetime remaining for this subscription.
        """
        return self._clamp_lifetime(self._get_lifetime(self.expiry))

    @property
    def is_expired(self):
        """
        Return true if the subscription has expired.
        """
        return self.lifetime <= 0

    @property
    def cost(self):
        """
        Route cost in arbitrary cost units.
        """
        return self._cost

    @property
    def expiry(self):
        """
        Absolute expiry time for this subscription.
        """
        return self._expiry

    @property
    def as_cbor_array(self):
        """
        Encode this subscription as a CBOR array.
        """
        return [self.lifetime, self.cost]

    def __iter__(self):
        """
        Iterate over the CBOR array representation.
        """
        return iter(self.as_cbor_array)

    def __repr__(self):
        """
        Return a representation of the subscription.
        """
        return "%s(expiry=%d, cost=%d)" % (
            self.__class__.__name__,
            self.expiry,
            self.cost,
        )


class EthernetFrameFragment(object):
    """
    Representation of an Ethernet frame fragment.
    """

    MAX_FRAME_ID = 65536
    MAX_TOTAL_SZ = 65536

    # Fragment size as CBOR:
    #   1 byte  start of 4-element array
    #  ≤3 bytes frame ID
    #  ≤3 bytes offset
    #  ≤3 bytes total_sz
    # N+3 bytes fragment data
    # N+13 worst case overhead
    FRAGMENT_SZ_OVERHEAD = 13

    @classmethod
    def make_fragments(
        cls, frame_id, max_sz, data, remain=None, enc=True, sign=False
    ):
        """
        Take the frame represented as raw bytes ``data``, and slice
        it into pieces that can be embedded into
        ``NodeEthernetTrafficNotification`` messages, taking into
        account MTU limits and the space available in the first
        payload message.
        """
        # Maximum available size: decrement for ENC0 and SIZE1 overheads
        # as applicable.
        if enc:
            max_sz -= ENC0_SZ_OVERHEAD
        if sign:
            max_sz -= SIGN1_SZ_OVERHEAD

        # We presume the first message may have the tail fragment of a
        # previous frame, hence it is smaller than the MTU.  If not given,
        # we assume the first message is empty.
        if remain is None:
            remain = max_sz
        elif remain > max_sz:
            raise ValueError("remaining size cannot be above MTU")

        # Start slicing up the data
        offset = 0
        total_sz = len(data)

        while data:
            fragment_sz = remain - cls.FRAGMENT_SZ_OVERHEAD
            fragment = data[:fragment_sz]

            yield cls(
                frame_id=frame_id,
                offset=offset,
                total_sz=total_sz,
                fragment_data=fragment,
            )

            data = data[fragment_sz:]
            offset += len(fragment)

            # Next frame
            remain = max_sz

    @classmethod
    def from_cbor_array(cls, array):
        return cls(
            frame_id=array[0],
            offset=array[1],
            total_sz=array[2],
            fragment_data=array[3],
        )

    def __init__(self, frame_id, offset, total_sz, fragment_data):
        if (frame_id < 0) or (frame_id >= self.MAX_FRAME_ID):
            raise ValueError("Frame ID out of range")
        if (total_sz < 0) or (total_sz >= self.MAX_TOTAL_SZ):
            raise ValueError("Total size out of range")
        if (offset < 0) or (offset >= total_sz):
            raise ValueError("Offset out of range")

        self._frame_id = frame_id
        self._offset = offset
        self._total_sz = total_sz
        self._fragment_data = bytes(fragment_data)

    @property
    def frame_id(self):
        return self._frame_id

    @property
    def offset(self):
        return self._offset

    @property
    def total_sz(self):
        return self._total_sz

    @property
    def fragment_data(self):
        return self._fragment_data

    @property
    def as_cbor_array(self):
        """
        Encode the fragment as a CBOR array
        """
        return [self.frame_id, self.offset, self.total_sz, self.fragment_data]


class NodeSharedKey(object):
    @classmethod
    def from_cbor_array(cls, array):
        kid = KeyID.decode(array[0])
        key = import_cose_key(array[1])
        packets = int(array[2])
        expiry = int(array[3])

        return cls(kid=kid, key=key, packets=packets, expiry=expiry)

    def __init__(
        self,
        kid,
        key,
        packets=KEY_PACKET_COUNT,
        lifetime=KEY_LIFETIME,
        expiry=None,
    ):
        if expiry is None:
            expiry = int(time.time() + expiry)

        self._kid = kid
        self._key = key
        self._packets = packets
        self._expiry = expiry

    @property
    def kid(self):
        return self._kid

    @property
    def purpose(self):
        return self._kid.purpose

    @property
    def key(self):
        return self._key

    @property
    def is_expired(self):
        if self.packets <= 0:
            return True
        if self.expiry <= time.time():
            return True
        return False

    @property
    def packets(self):
        return self._packets

    @property
    def expiry(self):
        return self._expiry

    def count_packet(self):
        self._packets -= 1

    @property
    def as_cbor_array(self):
        """
        Encode the key as CBOR array
        """
        return [bytes(self.kid), bytes(self.key), self.packets, self.expiry]


class NodeMsgType(enum.Enum):
    """
    Message type code.  Every message is headed with a code that describes
    the type of message being carried.
    """

    CAS = "CA"  # CA public key solicitation
    CAN = "ca"  # CA public key notification

    IDS = "ID"  # Identity solicitation
    IDN = "id"  # Identity notification

    PKS = "PK"  # Peer key solicitation
    PKN = "pk"  # Peer key notification

    PKVS = "PKV"  # Peer key verification solicitation
    PKVN = "pkv"  # Peer key verification notification

    KEYS = "SK"  # Sender key solicitation
    KEYN = "sk"  # Sender key notification

    MLS = "ML"  # MAC Listener solicitation
    MLN = "ml"  # MAC Listener notification

    ETN = "et"  # Ethernet traffic notification
    RRN = "rr"  # Request Refusal notification


class NodeMsgState(enum.ENUM):
    """
    State of the given message.  The message can be in one of the following
    states:

    Incoming messages:
    - UNDECODED: We have raw payload bytes, we have not tried to decode any of
      it.
    - OUTER_DECODED: We have decoded the outer message, but not verified or
      decrypted it.
    - INNER_DECODED: We have decoded the inner message, but decrypted it.
    - DECODED: We have decoded the message in full.

    Outgoing messages:
    - UNENCODED: We just have the bare original message.
    - CBOR_ENCODED: We have encoded the CBOR payload.
    - ENCRYPTED: We have encrypted the innermost message (or it wasn't needed).
    - ENCODED: We have encoded the outermost message for transmission.

    Unhappy path states:
    - UNVERIFIABLE: We tried verifying the message, but don't have the public
      key we need to validate the signature.
    - UNDECIPHERABLE: We tried decrypting the message, but don't have the
      symmetric key used to encrypt it.
    - UNPARSEABLE: The data is gibberish.
    """

    # Happy path: incoming
    UNDECODED = 0
    OUTER_DECODED = 1
    INNER_DECODED = 2
    DECODED = 3

    # Happy path: outgoing
    UNENCODED = 10
    CBOR_ENCODED = 11
    ENCRYPTED = 12
    ENCODED = 13

    # Unhappy path: incoming
    UNDECIPHERABLE = -2
    UNPARSEABLE = -3


class NodeMsg(object):
    """
    Container for the node message, wrapping layers and sender/receiver address.
    """

    @staticmethod
    def extract_kid(msg):
        """
        Extract the KID field from the given message.
        """
        if isinstance(msg, Sign1Message):
            # This is a signed message, find the KID in phdr
            kid = msg.phdr[KID]
        elif isinstance(msg, Enc0Message) or isinstance(msg, Mac0Message):
            # This is an encrypted or MAC-protected message, find the KID
            # in uhdr.
            kid = msg.uhdr[KID]
        else:
            raise TypeError("Message is not a COSE Sign1, Enc0 or MAC0")

        # Decode the KID
        return KeyID.decode(kid)

    def __init__(self, payload, msg):
        self._payload = payload
        self._msg = msg
        self._created = time.time()

    @property
    def created(self):
        """
        Return the time that this message was created.
        """
        return self._created

    @property
    def state(self):
        """
        Return the state of the message.
        """
        return self._state

    @property
    def payload(self):
        """
        The raw UDP message payload bytes, prior to being decoded or after
        encoding of the final outer message.
        """
        return self._payload

    @property
    def inner_payload(self):
        """
        The payload within the innermost message.
        """
        return self.inner.payload

    @property
    def msg(self):
        """
        The PVLAN message being decoded or encoded.
        """
        return self._msg


class MissingKeyError(KeyError):
    """
    The message is missing a symmetric key needed for decryption.
    """

    def __init__(self, kid, msg):
        super().__init__("Missing shared key %s" % kid)
        self._kid = kid
        self._msg = msg

    @property
    def kid(self):
        return self._kid

    @property
    def msg(self):
        return self._msg


class IncomingNodeMsg(NodeMsg):
    """
    Storage for incoming messages during decoding.  This container stores the
    various stages of message decoding so we can handle late arrival of
    cryptographic material.
    """

    def __init__(self, addr, payload):
        super().__init__(payload=payload, msg=None)
        self._addr = addr
        self._state = NodeMsgState.UNDECODED
        self._outer_verified = False
        self._inner_verified = False

        self._cbordata = None
        self._outer = None
        self._inner = None

        self._cert = None
        self._sharedkey = None
        self._sharedkeys = None

    @property
    def addr(self):
        """
        IP address where the message was received.
        """
        return self._addr

    @property
    def cert(self):
        """
        Certificate + public key used for SIGN1 validation.
        """
        return self._cert

    @property
    def sharedkey(self):
        """
        Symmetric key used for ENC0 decryption / MAC0 verification.
        """
        return self._sharedkey

    @property
    def verified(self):
        """
        Returns true if all validation checks have passed for this message.
        """
        if self.outer is None:
            return False

        if isinstance(self.outer, Sign1Message) and not self.outer_verified:
            return False

        if self.inner is None:
            return False

        return self.inner_verified

    @property
    def outer_verified(self):
        """
        Returns True if the outer Sign1 message has been verified.
        Not relevant for pure Enc0 / Mac0 messages.
        """
        return self._outer_verified

    @property
    def inner_verified(self):
        """
        Returns True if the inner Enc0 / Mac0 message has been checked.
        """
        return self._inner_verified

    @property
    def outer(self):
        """
        The outermost message envelope, which will be a COSE Sign1 or Enc0.
        """
        return self._outer

    @property
    def outer_kid(self):
        """
        Return the KID used to sign or encrypt the outermost message.
        """
        if self.outer:
            return self.extract_kid(self.outer)

        # No outer message frame
        return None

    @property
    def inner(self):
        """
        The innermost message envelope, which will either be a COSE Sign1
        (the same one as ``outer`` actually) or a COSE Enc1.
        """
        return self._inner

    @property
    def inner_kid(self):
        """
        Return the KID used to sign or encrypt the innermost message.
        """
        if self.inner:
            return self.extract_kid(self.inner)

        # No inner message frame
        return None

    @property
    def cbordata(self):
        """
        The CBOR data residing in the innermost message.
        """
        return self._cbordata

    def decode_outer(self):
        """
        Decode the outermost COSE message, if possible.
        """
        # Decode the outer message
        if self.outer is None:
            try:
                self._outer = CoseMessage.decode(self.payload)
            except:
                raise

            # Success, what did we get?
            if isinstance(self.outer, Sign1Message):
                # This is a digitally signed message.
                self._state = NodeMsgState.OUTER_DECODED
            else:
                # This is a Mac0 or Enc0, not signed.
                # Outer = Inner
                self._inner = self._outer
                self._state = NodeMsgState.INNER_DECODED

    def validate_outer(self, cert):
        """
        Validate the outer message with the given certificate.
        """
        if (not self.outer_verified) and isinstance(self.outer, Sign1Message):
            # We have a public key, try to validate the Sign1 with it.
            cert.pubkey.validate_sign1(self.outer)
            # Success, the message is valid.
            self._outer_verified = True

    def decode(self, cert=None, sharedkey=None, sharedkeys=None):
        """
        Decode the full message, if we can.
        """
        # Decode the outer message
        self.decode_outer()

        # Validate the outer message if we have a certificate to do that with.
        if cert is not None:
            self.validate_outer(cert)

        if self.inner is None:
            # See if we can decode the inner.
            try:
                self._inner = CoseMessage.decode(self.outer.payload)
                self._state = NodeMsgState.INNER_DECODED
            except AttributeError:
                # Raw CBOR?
                self._decode_cbor(self.outer.payload)
                # It is, so the outer is the innermost too
                self._inner = self.outer

        if self.cbordata is None:
            # Pick up the key used on the inner message
            kid = self.extract_kid(self.inner)
            if (sharedkey is None) and (sharedkeys is not None):
                sharedkey = sharedkeys.get(kid)

            if isinstance(self.inner, Enc0Message) and (sharedkey is None):
                # We can't proceed without the symmetric key!
                raise MissingKeyError(kid, self)

            # Validate the inner message
            self._validate_inner(sharedkey)

        if self.msg is None:
            # Try to parse the embedded message
            try:
                self._msg = NodeMsgBase.decode(self)
            except:
                # Nope!
                self._state = NodeMsgState.UNPARSEABLE
                raise

        return self.msg

    def _validate_inner(self, sharedkey):
        """
        Attempt validation (MAC0) or decryption (ENC0) with the given key.
        """
        if isinstance(self.inner, Mac0Message):
            sharedkey.key.validate_mac0(self.inner)
        else:
            assert isinstance(
                self.inner, Enc0Message
            ), "Not a MAC0 or ENC0, don't know how to proceed"
            self._decode_cbor(sharedkey.key.decrypt_enc0(self.inner))

        # This was it.
        self._inner_verified = True
        self._sharedkey = sharedkey

    def _decode_cbor(self, cborbytes):
        # Raw CBOR?
        try:
            self._cbordata = cbor2.loads(cborbytes)
            self._state = NodeMsgState.DECODED
        except:
            # Nope!
            self._state = NodeMsgState.UNPARSEABLE
            raise


class OutgoingNodeMsg(NodeMsg):
    """
    Storage for outgoing messages during encoding.
    """

    def __init__(self, msg):
        super().__init__(msg=msg, payload=None)
        self._state = NodeMsgState.UNENCODED
        self._inner_payload = None
        self._inner_kid = None
        self._outer_payload = None
        self._outer_kid = None

    @property
    def inner_payload(self):
        """
        The payload within the innermost message.
        """
        return self._inner_payload

    @property
    def inner_kid(self):
        """
        The key ID used to encode the innermost message.
        """
        return self._inner_kid

    @property
    def outer_payload(self):
        """
        The payload within the outermost message.
        """
        return self._outer_payload

    @property
    def outer_kid(self):
        """
        The key ID used to encode the outermost message.
        """
        return self._outer_kid

    def encode(
        self,
        privkey=None,
        kid=None,
        sharedkey=None,
        force_encrypt=False,
        force_sign=False,
    ):
        """
        Encode the inner message payload.
        """
        # Encode the message as CBOR
        if self.inner_payload is None:
            self._inner_payload = bytes(self.msg)
            self._state = NodeMsgState.CBOR_ENCODED

        # Encode the innermost ENC0 or MAC0
        if self.outer_payload is None:
            if force_encrypt or self.msg.ENCRYPTED:
                # Message must be encrypted, create a ENC0
                if sharedkey is None:
                    raise ValueError("sharedkey is required for encryption")

                if sharedkey.is_expired:
                    raise ValueError("provided shared key is expired")

                self._outer_payload = sharedkey.key.generate_enc0(
                    self.inner_payload, kid=bytes(sharedkey.kid)
                )
                self._outer_kid = sharedkey.kid
                sharedkey.count_packet()
            elif self.msg.AUTHENTICATED:
                # Message must be authenticated, create a MAC0
                if sharedkey is None:
                    raise ValueError(
                        "sharedkey is required for authentication"
                    )

                if sharedkey.is_expired:
                    raise ValueError("provided shared key is expired")

                self._outer_payload = sharedkey.key.generate_mac0(
                    self.inner_payload, kid=sharedkey.kid
                )
                self._outer_kid = sharedkey.kid
                sharedkey.count_packet()
            else:
                # Message has just an outermost Sign1
                self._outer_payload = self.inner_payload

            self._state = NodeMsgState.ENCRYPTED

        # Encode the outermost SIGN1
        if self.payload is None:
            if force_sign or self.msg.SIGNED:
                if privkey is None:
                    raise ValueError("privkey is required for signing")

                if kid is None:
                    raise ValueError("kid is required for signing")

                self._payload = privkey.generate_sign1(
                    self.outer_payload, kid=kid
                )
            else:
                # No signing necessary
                self._payload = self._outer_payload

            self._state = NodeMsgState.ENCODED

        # Return the encoded payload
        return self.payload


class NodeMsgBase(object):
    # Registry of node message type classes, for identification later
    _MSG_TYPES = {}

    # Default setting: require this message be digitally signed
    SIGNED = True

    # Default setting: require this message be encrypted
    ENCRYPTED = True

    # Default setting: we don't normally authenticate (with a MAC) a message
    AUTHENTICATED = False

    @staticmethod
    def extract_kid(msg):
        """
        Extract the KID field from the given message.
        """
        if isinstance(msg, Sign1Message):
            # This is a signed message, find the KID in phdr
            kid = msg.phdr[KID]
        elif isinstance(msg, Enc0Message) or isinstance(msg, Mac0Message):
            # This is an encrypted or MAC-protected message, find the KID
            # in uhdr.
            kid = msg.uhdr[KID]
        else:
            raise TypeError("Message is not a COSE Sign1, Enc0 or MAC0")

        # Decode the KID
        return KeyID.decode(kid)

    @classmethod
    def register(cls, typeclass):
        assert typeclass.MSG_TYPE not in cls._MSG_TYPES, (
            "Duplicate message type code: %r" % typeclass.MSG_TYPE
        )

        cls._MSG_TYPES[typeclass.MSG_TYPE] = typeclass
        return typeclass

    @classmethod
    def decode(cls, incoming):
        """
        Decode the incoming message.
        """
        # Decode the CBOR content
        if not isinstance(incoming.cbordata, list):
            raise ValueError("Node message is malformed")

        # First element is the message type
        msgtype = NodeMsgType(incoming.cbordata[0])

        # Second is the request ID
        rq_id = uuid.UUID(bytes=incoming.cbordata[1])

        typeclass = cls._MSG_TYPES[msgtype]
        return typeclass._decode(incoming, rq_id, incoming.cbordata[2:])

    def __init__(self, rq_id):
        self._rq_id = rq_id

    @property
    def rq_id(self):
        """
        Return the request ID.
        """
        return self._rq_id

    def __bytes__(self):
        """
        Encode the inner message payload.
        """
        return cbor2.dumps(
            [self.MSG_TYPE.value, self.rq_id.bytes] + self._get_payload()
        )


@NodeMsgBase.register
class NodeEthernetTrafficNotification(NodeMsgBase, Sequence):
    """
    Ethernet traffic notification.  This informs of the delivery of one
    or more frame fragments.
    """

    MSG_TYPE = NodeMsgType.ETN

    # Override setting: Digital signing is not necessary.
    SIGNED = False

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        return cls(
            rq_id,
            [
                EthernetFrameFragment.from_cbor_array(fragment)
                for fragment in payload
            ],
        )

    def __init__(self, rq_id, fragments):
        super().__init__(rq_id)

        self._fragment = fragments

    def __getitem__(self, idx):
        return self._fragment[idx]

    def __len__(self):
        return len(self._fragment)

    def _get_payload(self):
        return [fragment.as_cbor_array for fragment in self]


@NodeMsgBase.register
class NodeRequestRefusalNotification(NodeMsgBase):
    """
    Request Refusal notification, sent to a node in reply to a bad request.
    A numeric error code followed by a human-readable message is given.

    The error codes are taken from HTTP.
    """

    MSG_TYPE = NodeMsgType.RRN

    # Override setting: Encryption is not necessary.
    ENCRYPTED = False

    @classmethod
    def from_exc(cls, rq_id, exc):
        """
        Generate a refusal notification from an exception.
        """
        # TODO: better map out exceptions
        if isinstance(exc, (TypeError, ValueError)):
            # Their whoopsie!
            return cls(rq_id=rq_id, code=400, message=str(exc))
        else:
            # Our whoopsie!
            return cls(rq_id=rq_id, code=500, message=str(exc))

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        code = int(payload[0])
        message = str(payload[1])

        return cls(rq_id, code, message)

    def __init__(self, rq_id, code, message):
        super().__init__(rq_id)

        if (code < 400) or (code >= 600):
            raise ValueError("%d is not a valid error code" % code)

        self._code = code
        self._message = message

    @property
    def code(self):
        return self._code

    @property
    def message(self):
        return self._message

    def as_exc(self):
        """
        Translate to a sensible error code.
        """
        if self.code >= 500:
            # Internal error
            return IOError("%d: %s" % (self.code, self.message))
        elif self.code >= 400:
            # Request error
            return ValueError("%d: %s" % (self.code, self.message))

    def _get_payload(self):
        return [bytes(kid) for kid in self]


@NodeMsgBase.register
class NodeMsgCASolicitation(NodeMsgBase, Sequence):
    """
    CA solicitation, request the certificates of certificate authorities by
    the KIDs.  The KIDs are given as byte strings.

    The message is a COSE Sign1 message, with the KID pointing to the node
    keypair certificate.
    """

    MSG_TYPE = NodeMsgType.CAS

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        keylist = [KeyID.decode(kid) for kid in payload]

        return cls(rq_id, keylist)

    def __init__(self, rq_id, keylist):
        super().__init__(rq_id)
        self._keylist = keylist

    def __getitem__(self, idx):
        return self._keylist[idx]

    def __len__(self):
        return len(self._keylist)

    def _get_payload(self):
        return [bytes(kid) for kid in self]


@NodeMsgBase.register
class NodeMsgCANotification(NodeMsgBase, Mapping):
    """
    CA notification: This message returns the key certificates that were
    requested.  Payload format is:

    - Unrecognised KIDs: an array of KIDs that were not known by the sending
      station.
    - One or more CA certificates, given as COSE Sign1 objects.
    """

    MSG_TYPE = NodeMsgType.CAN

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        certs = dict((KeyID.decode(kid), None) for kid in payload[0])

        for certdata in payload[1:]:
            cert = KeyCertificate.decode(certdata)
            certs[cert.kid] = cert

        return cls(certs, rq_id=rq_id)

    def __init__(self, rq_id, certs):
        super().__init__(rq_id)
        self._certs = certs

    def __getitem__(self, keyid):
        return self._certs[keyid]

    def __iter__(self):
        return iter(self._certs)

    def __len__(self):
        return len(self._certs)

    def _get_payload(self):
        unrecognised_kids = []
        certs = []
        for kid, cert in self.items():
            if cert is None:
                unrecognised_kids.append(bytes(kid))
            else:
                certs.append(bytes(cert))

        return [unrecognised_kids] + certs


@NodeMsgBase.register
class NodeMsgIDSolicitation(NodeMsgBase):
    """
    ID solicitation, request a remote node identify itself to a remote party.
    As part of the interaction, the requesting node sends its own identity,
    consisting of:

    - its node host name (for human identification)
    - the node public key certificate
    - the user authorisation token (null if using host-only auth)
    - an unordered list of key IDs needed to validate the token and public
      key certificate.

    The message is a COSE Sign1 message, with the KID pointing to the key ID.
    """

    MSG_TYPE = NodeMsgType.IDS

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        kid = KeyID.decode(incoming.outer_kid)

        (
            name,
            certdata,
            authtoken,
        ) = payload[0:3]

        ca_keyids = set([KeyID.decode(kid) for kid in payload[3:]])

        if not isinstance(name, str):
            raise TypeError("name must be a text string")

        if authtoken is not None:
            raise ValueError("TODO: authtoken not implemented")

        cert = KeyCertificate.decode(certdata)

        return cls(name, kid, cert, ca_keyids)

    def __init__(self, rq_id, name, kid, cert, usertoken, ca_keyids):
        super().__init__(rq_id)
        self._name = name
        self._kid = kid
        self._cert = cert
        self._usertoken = usertoken
        self._ca_keyids = ca_keyids

    @property
    def name(self):
        return self._name

    @property
    def kid(self):
        return self._kid

    @property
    def cert(self):
        return self._cert

    @property
    def usertoken(self):
        return self._usertoken

    @property
    def ca_keyids(self):
        return self._ca_keyids

    def _get_payload(self):
        return [
            self.name,
            bytes(self.cert),
            bytes(self.usertoken) if self.usertoken else None,
        ] + [bytes(kid) for kid in self.ca_keyids]


@NodeMsgBase.register
class NodeMsgIDNotification(NodeMsgIDSolicitation):
    """
    ID notification, a response to an ID solicitation.  It carries the same
    data, just from the peer's perspective.

    - its node host name (for human identification)
    - the node public key certificate
    - the user authorisation token (null if using host-only auth)
    - an unordered list of key IDs needed to validate the token and public
      key certificate.

    The message is a COSE Sign1 message, with the KID pointing to the key ID.
    """

    MSG_TYPE = NodeMsgType.IDN


class NodeMsgPeerKeySolicitation(NodeMsgBase):
    """
    Peer Key solicitation, request a remote node to exchange a X25519 public
    key with us so we can negotiate a shared secret using ECDHE.  The payload
    just contains this node's X25519 public key, freshly generated.

    The message is a COSE Sign1 message.
    """

    MSG_TYPE = NodeMsgType.PKS

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        pubkey = SafeX25519PublicKey.from_bytes(payload[0])

        return cls(rq_id, pubkey)

    def __init__(self, rq_id, pubkey):
        super().__init__(rq_id)
        self._pubkey = pubkey

    @property
    def pubkey(self):
        return self._pubkey

    def _get_payload(self):
        return [bytes(self.pubkey)]


@NodeMsgBase.register
class NodeMsgPeerKeyNotification(NodeMsgBase):
    """
    Peer Key notification, send back our freshly generated X25519 public key,
    and some shared key parameters:

    - Derived key size (integer)
    - Algorithm name (text string)
    - Salt (randomised byte string)
    - Information (bigger randomised byte string)
    - Our public key
    - a nonce (randomised byte string)
    """

    MSG_TYPE = NodeMsgType.PKN

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    # Size of the nonce used for verification
    NONCE_SZ = 32

    # Parameters inherited from the base implementation
    DERIVED_KEY_SZ = SafeDerivedKey.DERIVED_KEY_SZ
    HASH_ALGO = SafeDerivedKey.HASH_ALGO
    SALT_SZ = SafeDerivedKey.SALT_SZ
    INFO_SZ = SafeDerivedKey.INFO_SZ

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        keysize = payload[0]
        if not isinstance(keysize, int):
            raise ValueError("Key size is not an integer")
        if keysize <= 0:
            raise ValueError("Key size must be greater than zero")

        algorithm = payload[1]
        if not isinstance(algorithm, str):
            raise ValueError("Algorithm must be a text string")

        salt = payload[2]
        if not isinstance(salt, bytes):
            raise ValueError("Salt must be a byte string")

        info = payload[3]
        if not isinstance(info, bytes):
            raise ValueError("Information must be a byte string")

        pubkey = SafeX25519PublicKey.from_bytes(payload[4])

        nonce = payload[5]
        if not isinstance(nonce, bytes):
            raise ValueError("Nonce must be a byte string")

        return cls(
            rq_id,
            pubkey=pubkey,
            keysize=keysize,
            algorithm=algorithm,
            salt=salt,
            info=info,
            nonce=nonce,
        )

    def __init__(
        self,
        rq_id,
        pubkey,
        keysize=DERIVED_KEY_SZ,
        salt=None,
        info=None,
        nonce=None,
        algorithm=HASH_ALGO,
        salt_sz=SALT_SZ,
        info_sz=INFO_SZ,
        nonce_sz=NONCE_SZ,
    ):
        super().__init__(rq_id)

        # Cast or generate salt, info and nonce
        salt = SafeRandomSecret.cast_or_generate(salt, salt_sz)
        info = SafeRandomSecret.cast_or_generate(info, info_sz)
        nonce = SafeRandomSecret.cast_or_generate(nonce, nonce_sz)

        self._keysize = keysize
        self._algorithm = algorithm
        self._salt = salt
        self._info = info
        self._pubkey = pubkey
        self._nonce = nonce

    @property
    def keysize(self):
        return self._keysize

    @property
    def algorithm(self):
        return self._algorithm

    @property
    def salt(self):
        return self._salt

    @property
    def info(self):
        return self._info

    @property
    def pubkey(self):
        return self._pubkey

    @property
    def nonce(self):
        return self._nonce

    def _get_payload(self):
        return [
            self.keysize,
            self.algorithm,
            bytes(self.salt),
            bytes(self.info),
            bytes(self.pubkey),
            bytes(self.nonce),
        ]


@NodeMsgBase.register
class NodeMsgPeerKeyVerificationSolicitation(NodeMsgBase):
    """
    Peer Key verification solicitation.  This contains a MAC0 of the nonce
    the peer sent us in the previous message, and a follow-up nonce of our
    own for the peer to send back as a MAC0.

    The message is a COSE Sign1 message.
    """

    MSG_TYPE = NodeMsgType.PKVS

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    # Size of the nonce used for verification, we make ours the same size!
    NONCE_SZ = NodeMsgPeerKeyNotification.NONCE_SZ

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        verification = payload[0]

        nonce = payload[1]
        if not isinstance(nonce, bytes):
            raise ValueError("Nonce must be a byte string")

        return cls(rq_id, verification=verification, nonce=nonce)

    def __init__(self, rq_id, verification, nonce=None, nonce_sz=NONCE_SZ):
        super().__init__(rq_id)

        # Dummy decode verification to check it is valid
        if not isinstance(CoseMessage.decode(verification), Mac0Message):
            raise ValueError("verification must be a COSE MAC0")

        # Generate a nonce if we don't have one
        nonce = SafeRandomSecret.cast_or_generate(nonce, nonce_sz)

        self._verification = verification
        self._nonce = nonce

    @property
    def verification(self):
        return self._verification

    @property
    def nonce(self):
        return self._nonce

    def _get_payload(self):
        return [self._verification, bytes(self.nonce)]


@NodeMsgBase.register
class NodeMsgPeerKeyVerificationNotification(NodeMsgBase):
    """
    Peer Key verification notification, send back a MAC0 of the nonce
    we were given to verify.
    """

    MSG_TYPE = NodeMsgType.PKVN

    # Override setting: Do not encrypt as we may not have the keys necessary
    # to do so at the time.  Still require digital signatures.
    ENCRYPTED = False

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        verification = payload[0]

        return cls(rq_id, verification=verification)

    def __init__(self, rq_id, verification):
        super().__init__(rq_id)

        # Dummy decode verification to check it is valid
        if not isinstance(CoseMessage.decode(verification), Mac0Message):
            raise ValueError("verification must be a COSE MAC0")

        self._verification = verification

    @property
    def verification(self):
        return self._verification

    def _get_payload(self):
        return [
            self._verification,
        ]


@NodeMsgBase.register
class NodeMsgSenderKeySolicitation(NodeMsgBase, Sequence):
    """
    Sender key solicitation, request the symmetric keys with the given KIDs
    being used for encrypting multicast traffic.

    The message is a COSE Enc0 message wrapped in a COSE Sign1.
    """

    MSG_TYPE = NodeMsgType.KEYS

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        keylist = [KeyID.decode(kid) for kid in payload]

        return cls(keylist, rq_id=rq_id)

    def __init__(self, rq_id, keylist):
        super().__init__(rq_id)
        self._keylist = keylist

    def __getitem__(self, idx):
        return self._keylist[idx]

    def __len__(self):
        return len(self._keylist)

    def _get_payload(self):
        return [bytes(kid) for kid in self]


@NodeMsgBase.register
class NodeMsgSenderKeyNotification(NodeMsgBase, Mapping):
    """
    Sender key notification: This message returns the sender keys that
    were requested.  Payload format is:

    - Unrecognised KIDs: an array of KIDs that were not known by the sending
      station.
    - One or more sender symmetric keys, given as plain CBOR objects embedding
      COSE symmetric keys.

    The payload must be delivered as an Enc0, wrapped in a Sign1.
    """

    MSG_TYPE = NodeMsgType.KEYN

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        keys = dict((KeyID.decode(kid), None) for kid in payload[0])

        for keydata in payload[1:]:
            key = NodeSharedKey.from_cbor_array(keydata)
            keys[key.kid] = key

        return cls(rq_id=rq_id, keys=keys)

    def __init__(self, rq_id, keys):
        super().__init__(rq_id)
        self._keys = keys

    def __getitem__(self, keyid):
        return self._keys[keyid]

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    def _get_payload(self):
        unrecognised_kids = []
        keys = []
        for kid, key in self.items():
            if key is None:
                unrecognised_kids.append(bytes(kid))
            else:
                keys.append(key.as_cbor_array)

        return [unrecognised_kids] + keys


@NodeMsgBase.register
class NodeMsgMACListenerSolicitation(NodeMsgBase, Set):
    """
    MAC Listener solicitation, a request for whomever is listening for
    one of the listed MAC addresses.

    The payload is:
    - first element: VLAN ID, or None for untagged
    - remainder: raw IEEE 802.3 (EUI-48) MAC addresses.

    The message is a COSE Enc0 message wrapped in a COSE Sign1.
    """

    MSG_TYPE = NodeMsgType.MLS

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        vlan = payload[0]
        maclist = [MAC.parse(macbytes) for macbytes in payload[1:]]

        return cls(maclist, rq_id=rq_id, vlan=vlan)

    def __init__(self, rq_id, maclist, vlan=None):
        super().__init__(rq_id)

        if vlan is not None:
            # Only pass the VLAN ID itself
            vlan &= VLANEthernetPayload.VLAN_MASK

        self._maclist = maclist
        self._vlan = vlan

    @property
    def vlan(self):
        return self._vlan

    def __contains__(self, mac):
        return mac in self._maclist

    def __len__(self):
        return len(self._maclist)

    def __iter__(self):
        return iter(self._maclist)

    def _get_payload(self):
        return [bytes(mac) for mac in self]


@NodeMsgBase.register
class NodeMsgMACListenerNotification(NodeMsgBase, Mapping):
    """
    MAC Listener notification, a statement of what MAC addresses this node is
    listening for.

    The payload is:

    - first element: VLAN ID, or None for untagged
    - subsequent elements: CBOR representation of MACSubscription (array)
      with the raw IEEE 802.3 EUI-48 (byte string) prepended.
      (i.e. [ MAC, LIFETIME, COST ]; 14 bytes each as CBOR)

    The message is a COSE Enc0 message wrapped in a COSE Sign1.
    """

    MSG_TYPE = NodeMsgType.MLN

    @staticmethod
    def _cast_subscription(sub):
        if isinstance(sub, int):
            return MACSubscription(sub)  # Default path cost
        elif isinstance(sub, dict):
            return MACSubscription(**sub)
        else:
            return MACSubscription(*sub)

    @classmethod
    def _decode(cls, incoming, rq_id, payload):
        return cls(
            rq_id=rq_id,
            maclifetimes=dict(
                (MAC.frombytes(sub[0]), MACSubscription(*sub[1:]))
                for sub in payload[1:]
            ),
            vlan=payload[0],
        )

    def __init__(self, rq_id, subscriptions, vlan=None):
        super().__init__(rq_id)

        if vlan is not None:
            # Only pass the VLAN ID itself
            vlan &= VLANEthernetPayload.VLAN_MASK

        self._vlan = vlan
        self._subscriptions = dict(
            (MAC.parse(mac), self._cast_subscription(sub))
            for mac, sub in subscriptions.items()
        )

    @property
    def vlan(self):
        return self._vlan

    def __getitem__(self, mac):
        return self._subscriptions[mac]

    def __iter__(self):
        return iter(self._subscriptions)

    def __len__(self):
        return len(self._subscriptions)

    def _get_payload(self):
        return [self.vlan] + [
            [bytes(mac)] + list(sub) for mac, sub in self.items()
        ]
