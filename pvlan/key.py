#!/usr/bin/env python3

"""
Key input/output, derivation and utility routines
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import weakref
import hashlib
import os

from pycose.keys import OKPKey, CoseKey, keytype
from pycose.keys.keyparam import KpKty, SymKpK, KpKeyOps

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secret import saltedsecret


# Functions for hashing public and private keys
PRIVKEY_HASH_FN = saltedsecret()


# Default curve to use for key generation
DEFAULT_CURVE = "ED25519"


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
            PRIVKEY_HASH_FN(self),
        )


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
        Return the key fingerprint for this key pair (SHA-256 hash of the
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
        Return the key fingerprint for this public key (SHA-256 hash).
        """
        if self._fingerprint is None:
            h = hashlib.sha256()
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
        Return a truncated SHA-256 hash of the public key for display
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


class SafeOKPPublicKey(PublicKeyMixin, SafeCOSEKeyWrapper):
    """
    A wrapped up COSE OKP public key.
    """

    pass


def load_cose_key(path):
    """
    Load a COSE-formatted key from a file.
    """
    with open(path, "rb") as f:
        key = CoseKey.decode(f.read())

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
    HASH_ALGO = "sha256"

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
        algorithm = getattr(hashes, algorithm.upper())

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
    HASH_ALGO = "sha256"

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
