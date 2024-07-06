#!/usr/bin/env python3

"""
PVLAN messaging
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import uuid
import time
import enum
from collections.abc import Mapping, Sequence

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


# Symmetric key lifetime
KEY_LIFETIME = 3600  # 1 hour
KEY_PACKET_COUNT = 100000  # packets

# Approximate ENC0 overhead, measured at ~66 bytes
ENC0_SZ_OVERHEAD = 66

# Approximate SIGN1 overhead, measured at ~99 bytes
SIGN1_SZ_OVERHEAD = 99


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

    ETN = "et"  # Ethernet traffic notification
    RRN = "rr"  # Request Refusal notification


class NodeMsgBase(object):
    # Registry of node message type classes, for identification later
    _MSG_TYPES = {}

    # Default setting: require this message be digitally signed
    SIGNED = True

    # Default setting: require this message be encrypted
    ENCRYPTED = True

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
    def decode(cls, outermsg, skeystore, nodecert=None):
        """
        Decode the message payload, up to two levels deep.
        The following forms are permitted:
        - Sign1 carrying CBOR:
            No inner message, innermsg and outermsg reference the same object
            Use cases:
            - CA key solicitation/notifications
            - ID solicitation/notifications
            - peer key solicitation/notifications and related acknowledgements
            - Sender key solicitation
            - Request refusal notification
        - Sign1 carrying a ENC0
            Sign1 is outermsg
            ENC0 is innermsg carrying CBOR
            Use cases:
            - Sender key notification
            - Ethernet traffic notification (signing enabled)
        - Bare ENC0 carrying CBOR
            No inner message, innermsg and outermsg reference the same object
            Use cases:
            - Ethernet traffic notification (signing disabled)

        Here, outermsg is the raw COSE sub-class, which must be either
        a Sign1 or ENC0 message.

        skeystore is a dict of all the symmetric keys sent by this node.  We
        choose any matching key that is not expired in the event we have an
        ENC0.

        nodecert is the public key certificate of the sending node, None if
        that is not yet known. (The message will not be validated if this is
        not provided!)
        """

        # outermsg is either a Sign1 or ENC0
        if isinstance(outermsg, Sign1Message):
            # Sign1: Should be signed with nodecert.pubkey
            if nodecert is not None:
                nodecert.pubkey.validate_sign1(outermsg)

            # payload is either raw CBOR or a ENC0
            try:
                innermsg = CoseMessage.decode(outermsg.payload)
                # We need the key to decrypt ENC0
                payload = None
            except AttributeError:
                # Nope, this is raw CBOR
                innermsg = outermsg
                payload = outermsg.payload
        elif isinstance(outermsg, Enc0Message):
            # Enc0 message, pretend it's the "inner" message
            innermsg = outermsg
            # We need the key to decrypt ENC0
            payload = None

        # innermsg is either raw CBOR or an ENC0
        if payload is None:
            # innermsg should be an ENC0
            if not isinstance(innermsg, Enc0Message):
                raise ValueError("Inner message not a COSE Sign1")

            # Retrieve its KID
            enc_kid = cls.extract_kid(innermsg)

            # Retrieve the key
            enc_key = skeystore[enc_kid]
            if enc_key.is_expired:
                raise ValueError("ENC0 key has expired")

            # Decrypt
            payload = enc_key.key.decrypt_enc0(innermsg)

        # Decode the CBOR content
        payload = cbor2.loads(payload)
        if not isinstance(payload, list):
            raise ValueError("Node message is malformed")

        # First element is the message type
        msgtype = NodeMsgType(payload[0])

        # Second is the request ID
        rq_id = uuid.UUID(bytes=payload[1])

        typeclass = cls._MSG_TYPES[msgtype]
        return typeclass._decode(outermsg, innermsg, rq_id, payload[2:])

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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
        kid = KeyID.decode(outermsg.phdr[KID])
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
    def _decode(cls, outermsg, innermsg, rq_id, payload):
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
