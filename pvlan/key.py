#!/usr/bin/env python3

"""
Key input/output, derivation and utility routines
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import argparse
import weakref
import hashlib
import os
import os.path
import enum
import uuid
from collections.abc import Mapping, Set

import cbor2

from pycose.algorithms import EdDSA, HMAC256, A256GCM
from pycose.headers import Algorithm, KID, IV
from pycose.keys import OKPKey, CoseKey, keytype
from pycose.keys.keyparam import KpKty, SymKpK, KpKeyOps
from pycose.messages import (
    Sign1Message,
    Enc0Message,
    Mac0Message,
    CoseMessage,
)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secret import saltedsecret, SALTED_SECRET_HASH_NAME


# Functions for hashing public and private keys
PRIVKEY_HASH_FN = saltedsecret()


# Default curve to use for key generation
DEFAULT_CURVE = "ED25519"


# References to every secret by identity.  So we can ensure the same ident
# never references two different secrets!
_SECRETS = weakref.WeakValueDictionary()


class KeyPurpose(enum.Enum):
    """
    Enumeration for describing the purpose of a key.  There are several key
    types for different occasions:

    - UNICAST keys are for one-to-one communications between two nodes and
      are used for all messages passed directly between those nodes.
    - MULTICAST keys are used for a node to encrypt messages it sends by
      multicast.  All other nodes will need a copy of this to decrypt the
      communications.
    - NODEAUTH keys are public keys used to authenticate the message from a
      given node.
    - USERAUTH keys are public keys used to authenticate the message from a
      given user.
    - TOKEN keys are public keys used to sign authorisation tokens.
    - CERTIFICATION keys are public keys used to authenticate all key types
    """

    UNICAST = 0
    MULTICAST = 1
    NODEAUTH = 2
    USERAUTH = 3
    TOKEN = 6
    CERTIFICATION = 7


class KeyID(object):
    """
    Representation of a key ID.
    """

    NODE_ID_POS = 0
    NODE_ID_LEN = 16
    PURPOSE_LEN = 1
    PURPOSE_POS = 16
    FINGERPRINT_POS = 17
    FINGERPRINT_LEN = 3

    KID_LEN = NODE_ID_LEN + PURPOSE_LEN + FINGERPRINT_LEN

    @classmethod
    def parse(cls, kidstr):
        """
        Decode a key ID from the text string
        """
        (uuidstr, kidhex, fphex) = kidstr.rsplit("-", 2)
        return cls(uuid.UUID(uuidstr), int(kidhex, 16), bytes.fromhex(fphex))

    @classmethod
    def decode(cls, kidbytes):
        """
        Decode a key ID from the byte string
        """
        if len(kidbytes) != cls.KID_LEN:
            raise ValueError("Improper KID length")

        owner_uuid = uuid.UUID(
            bytes=kidbytes[
                cls.NODE_ID_POS : cls.NODE_ID_POS + cls.NODE_ID_LEN
            ]
        )
        purpose = KeyPurpose(kidbytes[cls.PURPOSE_POS])
        fingerprint = kidbytes[-cls.FINGERPRINT_LEN :]

        return cls(owner_uuid, purpose, fingerprint)

    def __init__(self, owner_uuid, purpose, fingerprint):
        self._owner_uuid = owner_uuid
        self._purpose = purpose
        self._fingerprint = bytes(fingerprint)[0 : self.FINGERPRINT_LEN]

    @property
    def owner_uuid(self):
        """
        Return the owner UUID
        """
        return self._owner_uuid

    @property
    def purpose(self):
        """
        Return the key purpose
        """
        return self._purpose

    @property
    def fingerprint(self):
        """
        Return the (truncated) key fingerprint.
        """
        return self._fingerprint

    def __eq__(self, other):
        """
        Determine if the key ID is equivalent to another key ID.
        """
        return (
            (self.owner_uuid == other.owner_uuid)
            and (self.purpose == other.purpose)
            and (self.fingerprint == other.fingerprint)
        )

    def __bytes__(self):
        """
        Encode the key ID as bytes for the KID header.
        """
        return (
            self.owner_uuid.bytes
            + bytes([self.purpose.value])
            + self.fingerprint
        )

    def __str__(self):
        """
        Return a string representation of the key ID
        """
        return ("%s-%02x-%s") % (
            self.owner_uuid,
            self.purpose.value,
            self.fingerprint.hex(),
        )

    def __repr__(self):
        """
        Return a representation of the key ID
        """
        return (
            "%s(owner_uuid=%r, purpose=%s, fingerprint=bytes.fromhex(%r))"
        ) % (
            self.__class__.__name__,
            self.owner_uuid,
            self.purpose,
            self.fingerprint.hex(),
        )

    def __hash__(self):
        """
        Generate a hash of this key ID for indexing purposes.
        """
        return hash((self.owner_uuid, self.purpose, self.fingerprint))


class CertifiedObject(object):
    """
    A certified object is a data structure which has been signed by a
    certificate authority.
    """

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            return cls.decode(f.read())

    @staticmethod
    def _decode(objbytes):
        # Unpack the certified object
        certobject = CoseMessage.decode(objbytes)

        # Decode the payload
        payload = cbor2.loads(certobject.payload)

        # Return them for downstream processing
        return (certobject, payload)

    def __init__(self, certbytes, certobject):
        # Store the certified object as-is; this is a COSE Sign1, we cannot
        # re-generate this without the private key!
        self._certbytes = certbytes
        self._certobject = certobject

        # Retrieve the key signing information
        self._signed_kid = KeyID.decode(self._certobject.phdr[KID])
        self._signed_pubkey = None

    def __repr__(self):
        """
        Return a representation of the certified object
        """
        return ("<%s signed:%s %r>") % (
            self.__class__.__name__,
            self.signed_pubkey or self.signed_kid,
            self._certobject,
        )

    @property
    def signed_kid(self):
        """
        Return the key ID that signed this object.
        """
        return self._signed_kid

    @property
    def signed_pubkey(self):
        """
        Return the public key that certified this object.
        """
        return self._signed_pubkey

    def validate(self, cert, revoked_fps=None):
        """
        Validate against the given certification key certificate.  Throws a
        ``ValueError`` if certification fails.

        revoked_fps is ignored in the base class, but is used to check
        public key fingerprints against a revocation list in subclasses.
        """
        if self._signed_pubkey is cert:
            # We already did that
            return

        elif self._signed_pubkey is not None:
            raise ValueError(
                "Key already certified with %r" % self._signed_pubkey
            )

        if not isinstance(cert, CertificationKeyCertificate):
            raise TypeError(
                "Given certificate is not a certificatation key certificate"
            )

        # cert.pubkey is the SafeOKPPublicKey that signed the cert
        cert.pubkey.validate_sign1(self._certobject)

        # All checks out
        self._signed_pubkey = cert

    def validate_chain(self, keystore):
        """
        Validate the certificate, looking for all required keys in the given
        key store.  The key store is a dict keyed by KeyID.
        """
        # If the certificate store gives us a revocation list, grab that too
        try:
            revoked_fps = keystore.revoked_fps
        except AttributeError:
            # Assume nothing revoked
            revoked_fps = set()

        # Fetch the key that signed us
        cert = keystore[self.signed_kid]

        # Put these in the chain in order
        order = [self, cert]

        # Make a note of previously seen fingerprints
        seen = set([self.pubkey.fingerprint, cert.pubkey.fingerprint])

        while not cert.is_self_signed:
            # Move to its signing key
            cert = keystore[cert.signed_kid]

            # Check for loops
            fp = cert.pubkey.fingerprint
            if fp in seen:
                raise ValueError("Loop detected!")
            seen.add(fp)

            # Add it to the chain
            order.append(cert)

        # If we get here without KeyErrors, we have the whole chain.
        order.reverse()

        # Certify the root
        parent = order[0]
        assert parent.is_self_signed, "Discovered root is not self-signed!"
        parent.validate(parent, revoked_fps)

        # Certify the rest of the chain
        for cert in order[1:]:
            cert.validate(parent, revoked_fps)
            parent = cert

        # Return the validated certificate chain
        return order

    def __bytes__(self):
        """
        Return the certificate in encoded form.
        """
        return self._certbytes

    def save_cert(self, path):
        """
        Write the certificate to a file.
        """
        with open(path, "wb") as f:
            f.write(bytes(self))


class KeyCertificate(CertifiedObject):
    """
    A certificate representing a public key and its intended use case, signed
    by a certification key.  Yes, poor man's X509.

    The structure of the certificate is an array:
    - Key purpose
    - Public key data
    """

    @staticmethod
    def decode(certbytes):
        # Extract the certificate and payload
        (certificate, payload) = CertifiedObject._decode(certbytes)

        # Extract the purpose field
        purpose = KeyPurpose(payload[0])

        if purpose == KeyPurpose.CERTIFICATION:
            return CertificationKeyCertificate(
                certbytes, certificate, payload
            )
        else:
            return KeyCertificate(certbytes, certificate, purpose, payload)

    def __init__(self, certbytes, certificate, purpose, payload):
        super().__init__(certbytes, certificate)
        self._purpose = purpose

        # Extract key pieces of the certificate
        self._pubkey = import_cose_key(payload[1])

        # Sanity check
        if self._purpose not in (
            KeyPurpose.NODEAUTH,
            KeyPurpose.USERAUTH,
            KeyPurpose.CERTIFICATION,
        ):
            raise ValueError(
                "Certificates may not be used for %s keys"
                % self._purpose.label
            )

        if not isinstance(self._pubkey, SafeOKPPublicKey):
            raise ValueError("Certified key is not an OKP key")

    def __repr__(self):
        """
        Return a representation of the key certificate
        """
        return ("<%s key:%s purpose:%s signed:%s>") % (
            self.__class__.__name__,
            self.pubkey,
            self.purpose,
            self.signed_pubkey or self.signed_kid,
        )

    @property
    def purpose(self):
        """
        Return the purpose of this key, one of node/user authentication or
        key certification.
        """
        return self._purpose

    @property
    def pubkey(self):
        """
        Return the public key being certified.
        """
        return self._pubkey

    def get_kid(self, owner_uuid):
        """
        Return the KID for this public key given the owner UUID.
        """
        return KeyID(owner_uuid, self.purpose, self.pubkey.fingerprint)

    def validate(self, cert, revoked_fps=None):
        """
        Validate against the given certification key certificate.  Throws a
        ``ValueError`` if certification fails.
        """
        if (revoked_fps is not None) and (
            self.pubkey.fingerprint in revoked_fps
        ):
            raise ValueError("Certificate fingerprint is revoked")

        # Pass to superclass for digital signature verification
        super().validate(cert)


class RevocationCertificate(CertifiedObject, Set):
    """
    A revocation certificate is a list of keys that were revoked together
    at a given time.  The keys are specified by key fingerprint.
    """

    FILE_EXTN = ".pvrev"

    @classmethod
    def decode(cls, certbytes):
        # Extract the certificate and payload
        (certificate, payload) = CertifiedObject._decode(certbytes)
        return cls(certbytes, certificate, payload)

    def __init__(self, certbytes, certificate, payload):
        super().__init__(certbytes, certificate)
        self._keyfps = set(payload)

    def __contains__(self, keyid):
        return keyid in self._keyfps

    def __iter__(self):
        return iter(self._keyfps)

    def __len__(self):
        return len(self._keyfps)


class CertificationKeyCertificate(KeyCertificate):
    """
    A key certificate for certifying keys.  This has additional fields:

    - Authority UUID
    - Authority description
    """

    FILE_EXTN = ".pvccrt"

    def __init__(self, certbytes, certificate, payload):
        super().__init__(
            certbytes, certificate, KeyPurpose.CERTIFICATION, payload
        )

        self._authority_uuid = uuid.UUID(bytes=payload[2])
        self._authority_desc = payload[3]

        if not isinstance(self._authority_desc, str):
            raise ValueError("Description must be a text string")

    def __repr__(self):
        """
        Return a representation of the key certificate
        """
        return ("<%s %r uuid:%s key:%s signed:%s>") % (
            self.__class__.__name__,
            self.authority_desc,
            self.authority_uuid,
            self.pubkey,
            (
                "self"
                if self.is_self_signed
                else (self.signed_pubkey or self.signed_kid)
            ),
        )

    @property
    def is_self_signed(self):
        """
        Return true if this is a self-signed certificate.  (Root key)
        """
        return self.signed_kid == self.kid

    @property
    def kid(self):
        """
        Return this key's ID
        """
        return self.get_kid(self.authority_uuid)

    @property
    def authority_uuid(self):
        return self._authority_uuid

    @property
    def authority_desc(self):
        return self._authority_desc

    def get_kid(self, owner_uuid):
        """
        Return the KID for this public key.
        """
        if owner_uuid != self.authority_uuid:
            raise ValueError(
                "Certification keys must use the UUID of the authority"
            )
        return super().get_kid(owner_uuid)


class Keypair(object):
    """
    A class for storing a private/public key pair.
    """

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            return cls.decode(f.read())

    @classmethod
    def decode(cls, ckpbytes):
        # Unpack the certificate key pair
        (certdata, privkeydata) = cbor2.loads(ckpbytes)
        cert = KeyCertificate.decode(certdata)
        privkey = import_cose_key(privkeydata)
        return cls(cert, privkey)

    def __init__(self, cert, privkey):
        self._cert = cert
        self._privkey = privkey

    def __repr__(self):
        return "%s(%r, %r)" % (
            self.__class__.__name__,
            self._cert,
            self._privkey,
        )

    @property
    def privkey(self):
        """
        Return the private key for this key pair
        """
        return self._privkey

    @property
    def cert(self):
        """
        Return the public key for this key pair
        """
        return self._cert

    def save_keypair(self, path):
        """
        Write the key pair to a file.
        """
        with open(path, "wb") as f:
            f.write(cbor2.dumps([bytes(self._cert), bytes(self._privkey)]))

    def save_cert(self, path):
        """
        Write the public key certificate to a file.
        """
        self._cert.save_cert(path)


class CertificationKeypair(Keypair):
    """
    A class for storing a private/public certification key pair.
    """

    FILE_EXTN = ".pvckpr"

    @staticmethod
    def _gen_obj(decoder, privkey, kid, payload):
        """
        Generate a certificate with the given key ID and private key.
        """
        # Construct the certificate payload
        payload = cbor2.dumps(payload)

        # Encode and sign the payload
        encoded = privkey.generate_sign1(payload, phdr={KID: bytes(kid)})

        # Return the decoded certificate to sanity check
        return decoder(encoded)

    @classmethod
    def _gen_cert(cls, privkey, kid, purpose, pubkey, *args):
        """
        Generate a certificate with the given key ID and private key.
        """
        return cls._gen_obj(
            KeyCertificate.decode,
            privkey,
            kid,
            [purpose.value, bytes(pubkey)] + list(args),
        )

    @classmethod
    def generate_root(cls, authority_desc, authority_uuid=None):
        """
        Generate a new root certificate authority key pair.
        """
        if authority_uuid is None:
            authority_uuid = uuid.uuid4()

        privkey = SafeOKPPrivateKey.generate()
        pubkey = privkey.public
        kid = KeyID(
            authority_uuid, KeyPurpose.CERTIFICATION, pubkey.fingerprint
        )

        # Self-sign
        cert = cls._gen_cert(
            privkey,
            kid,
            KeyPurpose.CERTIFICATION,
            pubkey,
            authority_uuid.bytes,
            authority_desc,
        )

        # Verify for sanity
        cert.validate(cert)

        # Return the validated certificate
        return cls(cert, privkey)

    def generate_node_keypair(self):
        """
        Sign and generate a node keypair
        """
        # Generate the private key
        privkey = SafeOKPPrivateKey.generate()
        cert = self.generate_node(privkey.public)

        # Wrap the two up in a keypair
        return Keypair(cert, privkey)

    def generate_node(self, pubkey):
        """
        Sign and generate a certificate for this node public key.
        """
        # Generate the signed certificate
        cert = self._gen_cert(
            self._privkey, self._cert.kid, KeyPurpose.NODEAUTH, pubkey
        )

        # Verify for sanity
        cert.validate(self.cert)

        # Return the validated certificate
        return cert

    def generate_certification(
        self, pubkey, authority_desc, authority_uuid=None
    ):
        """
        Sign and generate a child certificate authority with the given key.
        """
        if authority_uuid is None:
            authority_uuid = uuid.uuid4()

        # Generate the signed certificate
        cert = self._gen_cert(
            self._privkey,
            self._cert.kid,
            KeyPurpose.CERTIFICATION,
            pubkey,
            authority_uuid.bytes,
            authority_desc,
        )

        # Verify for sanity
        cert.validate(self.cert)

        # Return the validated certificate
        return cert

    def generate_certification_keypair(
        self, authority_desc, authority_uuid=None
    ):
        """
        Generate a child CA.
        """
        privkey = SafeOKPPrivateKey.generate()
        cert = self.generate_certification(
            privkey.public, authority_desc, authority_uuid
        )
        return self.__class__(cert, privkey)

    def revoke_certs(self, *certs):
        """
        Revoke one or more certificates.
        """

        # Check they were in fact, issued by this CA first!
        for cert in certs:
            if cert.signed_pubkey is None:
                # Try validating against this CA
                cert.validate(self.cert)

            if cert.signed_kid != self.cert.kid:
                raise ValueError(
                    "Certificate %r not signed by this CA" % cert
                )

        # Generate the signed certificate
        revcert = self._gen_obj(
            RevocationCertificate.decode,
            self._privkey,
            self._cert.kid,
            [cert.pubkey.fingerprint for cert in certs],
        )

        # Verify for sanity
        revcert.validate(self.cert)

        # Return the validated certificate
        return revcert


class CertificateStore(Mapping):
    """
    A dict-like certificate store that automatically validates the
    certificates loaded into it.
    """

    def __init__(self, parent=None):
        self._parent = parent
        self._revoked_fps = set()
        self._certs = {}
        self._certs_fp = {}
        self._certs_ca = {}

    def __getitem__(self, keyid):
        try:
            return self._certs[keyid]
        except KeyError:
            if self._parent is None:
                raise
            return self._parent[keyid]

    def __iter__(self):
        return iter(self._keyset)

    def __len__(self):
        return len(self._keyset)

    @property
    def revoked_fps(self):
        """
        Return all of the revoked fingerprints known to this certificate
        store.
        """
        if self._parent:
            revoked = self._parent.revoked_fps
            revoked.update(self._revoked_fps)
        else:
            revoked = self._revoked_fps.copy()

        return revoked

    def get_cert_fp(self, fp):
        """
        Fetch a certificate by fingerprint.
        """
        try:
            return self._certs_fp[fp]
        except KeyError:
            if self._parent is None:
                raise
            return self._parent.get_cert_fp(fp)

    def add(self, *certs):
        """
        Add one or more certificates to the certificate store.  All
        certificates are validated prior to inclusion.
        """

        # We have the following keys accessible to us just now
        new_keys = dict((c.kid, c) for c in certs)

        while new_keys:
            certs = list(new_keys.values())
            changed = False

            for cert in certs:
                if not isinstance(cert, CertificationKeyCertificate):
                    raise TypeError(
                        "All certificates must be for certifications only"
                    )

                if cert.pubkey.fingerprint in self._revoked_fps:
                    # This key is revoked
                    new_keys.pop(cert.kid, None)
                    changed = True
                    continue

                # If the certificate is self-signed, validate it against
                # itself.  Otherwise, just validate it against our
                # existing validated certificates.
                if cert.is_self_signed:
                    cert.validate(cert)
                else:
                    # If the certificate depends on a new key, defer doing it
                    # for now.
                    if cert.signed_kid in new_keys:
                        continue

                    # Try validate this against the keys we know are valid
                    cert.validate_chain(self._certs)

                # If we're still here, it is valid, add it in, remove it
                # from the to-do list
                self._certs[cert.kid] = cert
                self._certs_fp[cert.pubkey.fingerprint] = cert
                self._certs_ca.setdefault(cert.signed_kid, []).append(cert)
                new_keys.pop(cert.kid, None)
                changed = True

            # If none were changed, we have a problem
            if not changed:
                break

        if new_keys:
            # There are left-overs, force-validate one to raise an error
            for cert in new_keys.values():
                cert.validate_chain(self._certs)

    def add_dir(
        self,
        path,
        cert_extn=CertificationKeyCertificate.FILE_EXTN,
        rev_extn=RevocationCertificate.FILE_EXTN,
    ):
        """
        Add all the certificates in the given directory.
        """
        loaded_key_certs = []
        loaded_rev_certs = []
        for name in os.listdir(path):
            (_, extn) = os.path.splitext(name)
            fullname = os.path.join(path, name)

            if extn == cert_extn:
                loaded_key_certs.append(KeyCertificate.load(fullname))
            elif extn == rev_extn:
                loaded_rev_certs.append(RevocationCertificate.load(fullname))

        self.add(*loaded_key_certs)
        self.apply_revocations(*loaded_rev_certs)

    def apply_revocations(self, *certs):
        """
        Apply the certificate revocations specified in the given revocation
        lists.
        """

        def _revoke(cert, certlist):
            fp = cert.pubkey.fingerprint
            kid = cert.kid
            self._revoked_fps.add(fp)
            self._certs.pop(kid, None)
            self._certs_fp.pop(fp, None)
            certlist.append(cert)

        revoked = []
        for cert in certs:
            # Firstly, validate it is valid
            cert.validate_chain(self._certs)

            # Iterate over all the fingerprints in the certificate
            for fp in cert:
                try:
                    match = self.get_cert_fp(fp)
                except KeyError:
                    # We don't have this one
                    continue

                # Was this certificate signed by the same CA?
                if match.signed_kid != cert.signed_kid:
                    # Nope!  So ignore it.
                    continue

                # Extra careful check
                if (
                    match.signed_pubkey.fingerprint
                    != cert.signed_pubkey.fingerprint
                ):
                    continue

                # Okay, good enough, rip it out.
                _revoke(match, revoked)

        # Check for any child certificates that are invalidated by this.
        while True:
            extra_revoked = []
            for cert in revoked:
                try:
                    child_certs = self._certs_ca[cert.kid]
                except KeyError:
                    continue

                # Revoke these too
                for ccert in child_certs:
                    _revoke(ccert, extra_revoked)

            if extra_revoked:
                revoked += extra_revoked
            else:
                # We're done
                break

        return revoked

    @property
    def _keyset(self):
        keys = set(self._certs.keys())
        if self._parent:
            keys |= set(self._parent.keys())
        return keys


class SafeSecret(object):
    """
    A wrapper around a raw secret to ensure safe usage.  Specifically,
    this routine hashes the key in representational views of the object so
    that no sensitive data is leaked.

    Some convenience methods are provided for getting a native representation
    and saving the key to disk.
    """

    def __init__(self, key):
        self._key = key
        self._repr = None
        self._ident = self._gen_ident()

    @property
    def ident(self):
        """
        Return the key identity (salted hash of the secret)
        """
        return bytes(self._ident)

    @property
    def key(self):
        """
        Return the key being wrapped.
        """
        return self._key

    def save_key(self, path):
        """
        Write the key to the given file path.
        """
        with open(path, "wb") as f:
            f.write(bytes(self))

    def __bytes__(self):
        """
        Return the key in its raw form.
        """
        return self._key

    def __repr__(self):
        """
        Return a representation that is safely logged.
        """
        if self._repr is None:
            self._repr = self._get_repr()
        return self._repr

    def _get_repr(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            self._ident,
        )

    def _gen_ident(self):
        """
        Generate a unique ident for this secret.
        """
        ident = PRIVKEY_HASH_FN(self)
        while ident in _SECRETS:
            # It matches an existing secret, is it the same?
            match = _SECRETS[ident]
            if bytes(match) == bytes(self):
                # It's the same secret, stop here
                break

            # Different secret!  Ookay, we need to add some more entropy!
            # Add 64 bits of random data for the hash and try again.
            ident = PRIVKEY_HASH_FN(bytes(self) + os.urandom(8))

        # Claim this identity (NB: we may also overwrite identical secrets)
        _SECRETS[ident] = self

        # Return the discovered identity.
        return ident


class PrivateKeyMixin(object):
    """
    A mix-in class that adds a reference to the public key counterpart.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._public = None

    @property
    def fingerprint(self):
        """
        Return the key fingerprint for this key pair (SHA3-512 hash of the
        public key).
        """
        return self.public.fingerprint

    @property
    def public(self):
        """
        Return the public key that corresponds to this private key.
        """
        if self._public:
            public = self._public()
        else:
            public = None

        if public is None:
            public = self._get_public_key()
            self._public = weakref.ref(public)

        return public


class PublicKeyMixin(object):
    """
    A mix-in class that adds a reference to the private key counterpart if
    known and tweaks the hash output.
    """

    def __init__(self, key, private=None, *args, **kwargs):
        super().__init__(key, *args, **kwargs)
        self._fingerprint = None
        if private is not None:
            self._private = weakref.ref(private)
        else:
            self._private = None

    @property
    def fingerprint(self):
        """
        Return the key fingerprint for this public key (SHA3-512 hash).
        """
        if self._fingerprint is None:
            h = hashlib.new(SALTED_SECRET_HASH_NAME)
            h.update(bytes(self))
            self._fingerprint = h.digest()
        return self._fingerprint

    @property
    def private(self):
        """
        Return the private key that corresponds to this public key, if known.
        """
        if self._private:
            return self._private()
        else:
            return None

    def _get_repr(self):
        """
        Return a truncated SHA3-512 hash of the public key for display
        purposes.  Not salted because public keys are not sensitive.
        """
        return "%s(%s)" % (
            self.__class__.__name__,
            self.fingerprint[:-8].hex(":", 2),
        )


# COSE Key classes and routines


class SafeCOSEKeyWrapper(SafeSecret):
    """
    A wrapper around COSE keys
    """

    def __bytes__(self):
        """
        Return the key encoded in COSE (CBOR) format.
        """
        return self.key.encode()


class SafeCOSESymmetricKey(SafeCOSEKeyWrapper):
    """
    A wrapped symmetric COSE key.
    """

    KEY_LENGTH_128 = 16
    KEY_LENGTH_192 = 24
    KEY_LENGTH_256 = 32

    @classmethod
    def generate(cls, length, *ops):
        """
        Generate a symmetric key from random data of the expected length.
        """
        return cls.from_bytes(os.urandom(length), *ops)

    @classmethod
    def from_bytes(cls, keydata, *ops):
        """
        Return a wrapped key from the given key data and key operation roles.
        Operation roles should be chosen from the classes in
        the ``pycose.keys.keyops`` module.
        """
        return cls(
            CoseKey.from_dict(
                {
                    KpKty: keytype.KtySymmetric,
                    SymKpK: keydata,
                    KpKeyOps: list(ops),
                }
            )
        )

    def generate_enc0(
        self,
        payload,
        algorithm=A256GCM,
        iv=None,
        iv_sz=16,
        phdr=None,
        uhdr=None,
        kid=None,
    ):
        """
        Generate a ENC0 message encrypted using this symmetric key.
        """
        # TODO: figure out iv_sz from the algorithm somehow.

        # Generate an IV if we do not have one yet
        iv = SafeRandomSecret.cast_or_generate(iv, iv_sz)

        # Construct the protected header
        _phdr = {Algorithm: algorithm, IV: bytes(iv)}

        if phdr is not None:
            _phdr.update(phdr)

        if kid is not None:
            # Construct a uhdr
            _uhdr = {KID: bytes(kid)}

            if uhdr is not None:
                _uhdr.update(uhdr)
        else:
            _uhdr = uhdr

        # Construct the message
        msg = Enc0Message(phdr=_phdr, uhdr=_uhdr, payload=payload)
        msg.key = self.key
        return msg.encode()

    def decrypt_enc0(self, msg):
        """
        Decrypt a ENC0 message encrypted using this symmetric key.
        """
        if not isinstance(msg, Enc0Message):
            # Decode the bytes to an object
            msg = CoseMessage.decode(msg)

        msg.key = self.key
        return msg.decrypt()

    def generate_mac0(
        self, payload, algorithm=HMAC256, phdr=None, uhdr=None, kid=None
    ):
        """
        Generate a MAC0 message keyed using this symmetric key.
        """
        # Construct the protected header
        _phdr = {Algorithm: algorithm}
        if phdr is not None:
            _phdr.update(phdr)

        if kid is not None:
            # Construct a uhdr
            _uhdr = {KID: bytes(kid)}

            if uhdr is not None:
                _uhdr.update(uhdr)
        else:
            _uhdr = uhdr

        # Construct the message
        msg = Mac0Message(phdr=_phdr, uhdr=_uhdr, payload=payload)
        msg.key = self.key
        return msg.encode()

    def validate_mac0(self, msg):
        """
        Validate a MAC0 message keyed using this symmetric key.
        """
        if not isinstance(msg, Mac0Message):
            # Decode the bytes to an object
            msg = CoseMessage.decode(msg)

        msg.key = self.key
        if msg.verify_tag():
            return msg
        else:
            raise ValueError(
                "MAC0 message %r tag does not match key %r" % (msg, self)
            )


class SafeOKPPrivateKey(PrivateKeyMixin, SafeCOSEKeyWrapper):
    """
    A wrapped up COSE OKP private key.
    """

    @classmethod
    def generate(cls, crv=DEFAULT_CURVE):
        return cls(OKPKey.generate_key(crv=crv))

    def _get_public_key(self):
        return SafeOKPPublicKey(
            key=OKPKey.from_dict(
                {
                    "CURVE": self.key.crv,
                    "X": self.key.x,
                }
            ),
            private=self,
        )

    def generate_sign1(self, payload, phdr=None, uhdr=None, kid=None):
        """
        Generate a COSE Sign1 message using this private key.
        """
        # Construct the protected header
        _phdr = {Algorithm: EdDSA}

        if kid is not None:
            _phdr[KID] = bytes(kid)

        if phdr is not None:
            _phdr.update(phdr)

        # Construct the message
        msg = Sign1Message(phdr=_phdr, uhdr=uhdr, payload=payload)
        msg.key = self.key

        # Encode
        return msg.encode()


class SafeOKPPublicKey(PublicKeyMixin, SafeCOSEKeyWrapper):
    """
    A wrapped up COSE OKP public key.
    """

    def validate_sign1(self, msg):
        """
        Validate a COSE Sign1 message using this public key.
        """
        if not isinstance(msg, Sign1Message):
            # Decode the bytes to an object
            msg = CoseMessage.decode(msg)

        # Assign the key
        msg.key = self.key

        # Validate
        if msg.verify_signature():
            return msg
        else:
            raise ValueError(
                "Bad signature: Message %r does not match key %r"
                % (msg, self)
            )


def import_cose_key(keydata):
    """
    Load a COSE-formatted key from a byte string.
    """
    key = CoseKey.decode(keydata)

    if key.kty == keytype.KtyOKP:
        # OKP key
        if key.d:
            # This is a private key
            return SafeOKPPrivateKey(key)
        else:
            # This is a public key
            return SafeOKPPublicKey(key)
    elif key.kty == keytype.KtySymmetric:
        # Symmetric key: MAC0 or encryption
        return SafeCOSESymmetricKey(key)
    # elif key.kty == keytype.KtyEC2:
    #   TODO: implement EC2 if needed
    else:
        raise NotImplementedError("%s not supported" % key.kty)


def load_cose_key(path):
    """
    Load a COSE-formatted key from a file.
    """
    with open(path, "rb") as f:
        return import_cose_key(f.read())


# X25519 key routines and classes, no loader for these because we never
# persist X25519 keys.


class SafeRandomSecret(SafeSecret):
    @classmethod
    def generate(cls, length):
        return cls(os.urandom(length))

    @classmethod
    def cast_or_generate(cls, key, length):
        if key is None:
            return cls.generate(length)
        else:
            return cls(bytes(key))


class SafeDerivedKey(SafeSecret):
    SALT_SZ = 32
    INFO_SZ = 256
    DERIVED_KEY_SZ = 32

    # Lower-case, for consistency with hashlib!
    HASH_ALGO = SALTED_SECRET_HASH_NAME

    @classmethod
    def generate(
        cls,
        privkey,
        pubkey,
        derived_key_sz=DERIVED_KEY_SZ,
        salt=None,
        info=None,
        algorithm=HASH_ALGO,
        salt_sz=SALT_SZ,
        info_sz=INFO_SZ,
    ):
        """
        Using the given information, derive a shared secret.
        """
        # Retrieve the algorithm
        algorithm = getattr(hashes, algorithm.upper())()

        # Cast or generate salt and info
        salt = SafeRandomSecret.cast_or_generate(salt, salt_sz)
        info = SafeRandomSecret.cast_or_generate(info, info_sz)

        # Generate shared key
        shared_key = privkey.key.exchange(pubkey.key)

        # Perform key derivation
        key = HKDF(
            algorithm=algorithm,
            length=derived_key_sz,
            salt=salt.key,
            info=info.key,
        ).derive(shared_key)

        # Return a wrapped key
        return cls(key=key, salt=salt, info=info)

    def __init__(self, key, salt, info):
        super().__init__(key=key)
        self._salt = salt
        self._info = info

    @property
    def salt(self):
        """
        Return the salt used to generate this shared key.
        """
        return self._salt

    @property
    def info(self):
        """
        Return the info field used to generate this shared key.
        """
        return self._info

    def as_cose_key(self, *ops):
        """
        Return this key as a COSE symmetric key for the given operations.
        """
        return SafeCOSESymmetricKey.from_bytes(self.key, *ops)


class SafeX25519PrivateKey(PrivateKeyMixin, SafeSecret):
    """
    A wrapped up X25519 private key.
    """

    SALT_SZ = 32
    INFO_SZ = 256
    DERIVED_KEY_SZ = 32

    # Lower-case, for consistency with hashlib!
    HASH_ALGO = SALTED_SECRET_HASH_NAME

    @classmethod
    def generate(cls):
        return cls(X25519PrivateKey.generate())

    def exchange_and_derive(self, pubkey, *args, **kwargs):
        """
        Performs a key exchange operation using the given public key then
        derive a safe secret.
        """
        return SafeDerivedKey.generate(self, pubkey, *args, **kwargs)

    def __bytes__(self):
        return self.key.private_bytes_raw()

    def _get_public_key(self):
        return SafeX25519PublicKey(
            key=self.key.public_key(),
            private=self,
        )


class SafeX25519PublicKey(PublicKeyMixin, SafeSecret):
    """
    A wrapped up X25519 private key.
    """

    @classmethod
    def from_bytes(cls, key):
        """
        Retrieve a public key given as raw bytes.
        """
        return cls(X25519PublicKey.from_public_bytes(key))

    def __bytes__(self):
        return self.key.public_bytes_raw()


def keymgr_main():
    """
    Key manager: a CLI tool for generating and managing keys.
    """

    def _rev_list(log, args):
        revcrt = RevocationCertificate.load(args.rev_cert)
        for fp in revcrt:
            print(fp.hex(":", 2))

    def _key_generate(log, args):
        log.info("Creating a private key in %s", args.privkey)
        if os.path.exists(args.privkey):
            log.warning("Existing private key will be overwritten!")

        key = SafeOKPPrivateKey.generate()
        key.save_key(args.privkey)

    def _key_getpub(log, args):
        log.info("Retrieving the public key in %s", args.privkey)
        if os.path.exists(args.pubkey):
            log.warning("Existing public key will be overwritten!")

        key = load_cose_key(args.privkey)
        key.public.save_key(args.pubkey)

    def _kp_assemble(log, args):
        log.info("Assembling a keypair %s", args.keypair)
        if os.path.exists(args.keypair):
            log.warning("Existing key pair will be overwritten!")

        cert = KeyCertificate.load(args.cert)
        key = load_cose_key(args.privkey)
        kp = Keypair(cert, key)
        kp.save_keypair(args.keypair)

    def _kp_getpriv(log, args):
        log.info("Retrieving the private key in %s", args.keypair)
        if os.path.exists(args.privkey):
            log.warning("Existing private key will be overwritten!")

        kp = Keypair.load(args.keypair)
        kp.privkey.save_key(args.privkey)

    def _kp_getcert(log, args):
        log.info("Retrieving the certificate in %s", args.keypair)
        if os.path.exists(args.cert):
            log.warning("Existing certificate will be overwritten!")

        kp = Keypair.load(args.keypair)
        kp.cert.save_cert(args.cert)

    def _kp_info(log, args):
        kp = Keypair.load(args.keypair)
        print("Purpose: %s" % kp.cert.purpose.name)
        print("FP: %s" % kp.cert.pubkey.fingerprint.hex(":", 2))

    def _ca_info(log, args):
        kp = CertificationKeypair.load(args.keypair)
        print("Description: %s" % kp.cert.authority_desc)
        print("UUID: %s" % kp.cert.authority_uuid)
        print("KID: %s" % kp.cert.kid)
        print("FP: %s" % kp.cert.pubkey.fingerprint.hex(":", 2))

    def _ca_gen_root(log, args):
        log.info(
            "Creating a new CA (%r) in %s", args.description, args.keypair
        )
        if os.path.exists(args.keypair):
            log.warning("Existing keypair will be overwritten!")

        authority_uuid = uuid.UUID(args.uuid) if args.uuid else None

        kp = CertificationKeypair.generate_root(
            authority_desc=args.description, authority_uuid=authority_uuid
        )
        kp.save_keypair(args.keypair)

    def _ca_generate_child(log, args):
        log.info(
            "Creating a child CA (%r) in %s of the CA in %s",
            args.description,
            args.child_keypair,
            args.keypair,
        )
        if os.path.exists(args.child_keypair):
            log.warning("Existing keypair will be overwritten!")

        authority_uuid = uuid.UUID(args.uuid) if args.uuid else None

        pkp = CertificationKeypair.load(args.keypair)
        ckp = pkp.generate_certification_keypair(
            authority_desc=args.description, authority_uuid=authority_uuid
        )
        ckp.save_keypair(args.child_keypair)

    def _ca_sign_child(log, args):
        log.info(
            "Signing a child CA (%r) in %s of the CA in %s",
            args.description,
            args.child_cert,
            args.keypair,
        )
        if os.path.exists(args.child_cert):
            log.warning("Existing certificate will be overwritten!")

        authority_uuid = uuid.UUID(args.uuid) if args.uuid else None

        pubkey = load_cose_key(args.child_pubkey)

        pkp = CertificationKeypair.load(args.keypair)
        crt = pkp.generate_certification(
            pubkey=pubkey,
            authority_desc=args.description,
            authority_uuid=authority_uuid,
        )
        crt.save_cert(args.child_cert)

    def _ca_generate_node(log, args):
        log.info(
            "Creating a node keypair in %s of the CA in %s",
            args.node_keypair,
            args.keypair,
        )
        if os.path.exists(args.node_keypair):
            log.warning("Existing keypair will be overwritten!")

        pkp = CertificationKeypair.load(args.keypair)
        ckp = pkp.generate_node_keypair()
        ckp.save_keypair(args.node_keypair)

    def _ca_sign_node(log, args):
        log.info(
            "Signing a node certificate in %s of the CA in %s",
            args.node_cert,
            args.keypair,
        )
        if os.path.exists(args.node_cert):
            log.warning("Existing certificate will be overwritten!")

        pubkey = load_cose_key(args.node_pubkey)

        pkp = CertificationKeypair.load(args.keypair)
        crt = pkp.generate_node(pubkey=pubkey)
        crt.save_cert(args.node_cert)

    def _ca_revoke(log, args):
        log.info(
            "Revoking keys signed by the CA %s",
            args.keypair,
        )
        if os.path.exists(args.rev_cert):
            log.warning(
                "Existing revocation certificate will be overwritten!"
            )

        pkp = CertificationKeypair.load(args.keypair)

        certs = []
        for certpath in args.certs:
            log.debug("Reading certificate in %s", certpath)
            try:
                cert = KeyCertificate.load(certpath)
            except AttributeError:
                # Did we get given a keypair instead?
                kp = Keypair.load(certpath)
                cert = kp.cert

            cert.validate(pkp.cert)

            log.info("Will revoke ID %s", cert.pubkey.fingerprint.hex(":", 2))
            certs.append(cert)

        revcrt = pkp.revoke_certs(*certs)
        revcrt.save_cert(args.rev_cert)
        log.info("Written to %s", args.rev_cert)

    ap = argparse.ArgumentParser(
        description="Manage PVLAN cryptographic keys"
    )
    ap.add_argument(
        "--log-level",
        help="Logging level",
        type=str,
        default="info",
        choices=("debug", "info", "warning", "error", "fatal"),
    )
    ap_sub = ap.add_subparsers(help="sub-command help", required=True)

    ap_rev_list = ap_sub.add_parser(
        "rev_list", help="List the contents of a revocation certificate"
    )
    ap_rev_list.set_defaults(fn=_rev_list, logger="pvlan.rev_list")
    ap_rev_list.add_argument("rev_cert", help="Revocation certificate file")

    ap_key = ap_sub.add_parser(
        "key", help="Perform operations on bare private keys"
    )
    ap_key_sub = ap_key.add_subparsers(required=True)

    ap_key_gen = ap_key_sub.add_parser(
        "generate", help="Generate a private key"
    )
    ap_key_gen.set_defaults(fn=_key_generate, logger="pvlan.key.gen")
    ap_key_gen.add_argument("privkey", help="Path to private key")

    ap_key_getpub = ap_key_sub.add_parser(
        "getpub", help="Extract a public key"
    )
    ap_key_getpub.set_defaults(fn=_key_getpub, logger="pvlan.key.getpub")
    ap_key_getpub.add_argument("privkey", help="Path to private key")
    ap_key_getpub.add_argument("pubkey", help="Path to public key")

    ap_kp = ap_sub.add_parser("kp", help="Perform operations on keypairs")
    ap_kp.add_argument("keypair", help="Path to keypair")

    ap_kp_sub = ap_kp.add_subparsers(required=True)

    ap_kp_assemble = ap_kp_sub.add_parser(
        "assemble",
        help="Assemble a keypair from a certificate and a private key",
    )
    ap_kp_assemble.set_defaults(fn=_kp_assemble, logger="pvlan.kp.assemble")
    ap_kp_assemble.add_argument("cert", help="Path to signed certificate")
    ap_kp_assemble.add_argument("privkey", help="Path to private key")

    ap_kp_getpriv = ap_kp_sub.add_parser(
        "getpriv", help="Extract a private key"
    )
    ap_kp_getpriv.set_defaults(fn=_kp_getpriv, logger="pvlan.kp.getpriv")
    ap_kp_getpriv.add_argument("privkey", help="Path to private key")

    ap_kp_getcert = ap_kp_sub.add_parser(
        "getcert", help="Extract a public key"
    )
    ap_kp_getcert.set_defaults(fn=_kp_getcert, logger="pvlan.kp.getcert")
    ap_kp_getcert.add_argument("cert", help="Path to certificate")

    ap_kp_getfp = ap_kp_sub.add_parser("info", help="Dump keypair info")
    ap_kp_getfp.set_defaults(fn=_kp_info, logger="pvlan.kp.info")

    ap_ca = ap_sub.add_parser("ca", help="Perform operations as a CA")
    ap_ca.add_argument("keypair", help="Keypair file storing the CA keys")

    ap_ca_sub = ap_ca.add_subparsers(required=True)

    ap_ca_info = ap_ca_sub.add_parser("info", help="Dump CA information")
    ap_ca_info.set_defaults(fn=_ca_info, logger="pvlan.key.ca.info")

    ap_ca_gen_root = ap_ca_sub.add_parser(
        "gen_root", help="Generate a new CA"
    )
    ap_ca_gen_root.set_defaults(
        fn=_ca_gen_root, logger="pvlan.key.ca.gen.root"
    )
    ap_ca_gen_root.add_argument("description", help="CA description")
    ap_ca_gen_root.add_argument("uuid", help="CA UUID", nargs="?")

    ap_ca_generate_child = ap_ca_sub.add_parser(
        "gen_child", help="Generate a child CA"
    )
    ap_ca_generate_child.set_defaults(
        fn=_ca_generate_child, logger="pvlan.key.ca.gen.child"
    )
    ap_ca_generate_child.add_argument(
        "child_keypair", help="Path to the child keypair"
    )
    ap_ca_generate_child.add_argument("description", help="CA description")
    ap_ca_generate_child.add_argument("uuid", help="CA UUID", nargs="?")

    ap_ca_sign_child = ap_ca_sub.add_parser(
        "sign_child", help="Generate a child CA from existing public key"
    )
    ap_ca_sign_child.set_defaults(
        fn=_ca_sign_child, logger="pvlan.key.ca.sign.child"
    )
    ap_ca_sign_child.add_argument(
        "child_pubkey", help="Path to the child public key"
    )
    ap_ca_sign_child.add_argument(
        "child_cert", help="Path to the child certificate to generate"
    )
    ap_ca_sign_child.add_argument("description", help="CA description")
    ap_ca_sign_child.add_argument("uuid", help="CA UUID", nargs="?")

    ap_ca_generate_node = ap_ca_sub.add_parser(
        "gen_node", help="Generate a node keypair"
    )
    ap_ca_generate_node.set_defaults(
        fn=_ca_generate_node, logger="pvlan.key.ca.gen.node"
    )
    ap_ca_generate_node.add_argument(
        "node_keypair", help="Path to the node keypair"
    )

    ap_ca_sign_node = ap_ca_sub.add_parser(
        "sign_node",
        help="Generate a node certificate from existing public key",
    )
    ap_ca_sign_node.set_defaults(
        fn=_ca_sign_node, logger="pvlan.key.ca.sign.node"
    )
    ap_ca_sign_node.add_argument(
        "node_pubkey", help="Path to the node public key"
    )
    ap_ca_sign_node.add_argument(
        "node_cert", help="Path to the node certificate to generate"
    )

    ap_ca_revoke = ap_ca_sub.add_parser(
        "revoke",
        help="Generate a revocation certificate for the given certificates",
    )
    ap_ca_revoke.set_defaults(fn=_ca_revoke, logger="pvlan.key.ca.revoke")
    ap_ca_revoke.add_argument(
        "rev_cert", help="Path to the revocation certificate"
    )
    ap_ca_revoke.add_argument(
        "certs", help="Path to the certificates to revoke", nargs="+"
    )

    args = ap.parse_args()
    logging.basicConfig(level=args.log_level.upper())

    args.fn(logging.getLogger(args.logger), args)


if __name__ == "__main__":
    keymgr_main()
