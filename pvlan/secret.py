#!/usr/bin/env python3

"""
Secret handling functions, for keeping secrets out of logs!
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import hashlib


SALTED_SECRET_HASH_NAME = "sha3_512"
SALTED_SECRET_ITERATIONS = 100
SALTED_SECRET_SALTLEN = 32
SALTED_SECRET_LEN = 8
SALTED_SECRET_SEP = ":"
SALTED_SECRET_SEPBYTES = 2


class SaltedSecret(object):
    """
    A secret that has been salted.  Stores the byte representation and
    a visual string representation of the same secret.
    """

    def __init__(
        self,
        hashedsecret,
        sep=SALTED_SECRET_SEP,
        sepbytes=SALTED_SECRET_SEPBYTES,
    ):
        self._hashedsecret = hashedsecret
        self._sep = sep
        self._sepbytes = sepbytes

    @property
    def sep(self):
        """
        Separator to use in string representation of the secret.
        """
        return self._sep

    @property
    def sepbytes(self):
        """
        Number of bytes to use between separators in the string
        representation.
        """
        return self._sepbytes

    def __bytes__(self):
        return self._hashedsecret

    def __hash__(self):
        return hash(bytes(self))

    def __repr__(self):
        return bytes(self).hex(self.sep, self.sepbytes)


def saltedsecret(
    hash_name=SALTED_SECRET_HASH_NAME,
    iterations=SALTED_SECRET_ITERATIONS,
    saltlen=SALTED_SECRET_SALTLEN,
    length=SALTED_SECRET_LEN,
    sep=SALTED_SECRET_SEP,
    sepbytes=SALTED_SECRET_SEPBYTES,
):
    """
    Make a hash function that will hash the secrets passed to it.
    """
    salt = os.urandom(saltlen)

    return lambda p: SaltedSecret(
        hashedsecret=hashlib.pbkdf2_hmac(
            hash_name=hash_name,
            password=bytes(p),
            salt=salt,
            iterations=iterations,
        )[-length:],
        sep=sep,
        sepbytes=sepbytes,
    )
