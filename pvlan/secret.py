#!/usr/bin/env python3

"""
Secret handling functions, for keeping secrets out of logs!
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0

import os
import hashlib


def saltedsecret(
    hash_name="sha256",
    iterations=100,
    saltlen=32,
    length=8,
    sep=":",
    sepbytes=2,
):
    """
    Make a hash function that will hash the secrets passed to it.
    """
    salt = os.urandom(saltlen)

    return lambda p: hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=bytes(p),
        salt=salt,
        iterations=iterations,
    )[:-length].hex(sep, sepbytes)
