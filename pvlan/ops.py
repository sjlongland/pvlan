#!/usr/bin/env python3

"""
PVLAN operations
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import uuid

from pycose.keys.keyops import MacCreateOp, MacVerifyOp, EncryptOp, DecryptOp
from pycose.headers import KID

from .msg import (
    NodeSharedKey,
    NodeMsgCASolicitation,
    NodeMsgCANotification,
    NodeMsgIDSolicitation,
    NodeMsgIDNotification,
    NodeMsgPeerKeySolicitation,
    NodeMsgPeerKeyNotification,
    NodeMsgPeerKeyVerificationSolicitation,
    NodeMsgPeerKeyVerificationNotification,
    NodeMsgSenderKeySolicitation,
    NodeMsgSenderKeyNotification,
    NodeMsgMACListenerSolicitation,
    NodeMsgMACListenerNotification,
    NodeRequestRefusalNotification,
)

from .key import SafeX25519PrivateKey, KeyPurpose, KeyID

# Time-out in seconds
OP_TIMEOUT = 60.0


class NodeOpBase(object):
    """
    Node Operation base class, this is a state machine handler that performs
    actions such as retrieving the identity of a given node.
    """

    def __init__(self, ownnode, targetnode, future):
        self._ownnode = ownnode
        self._targetnode = targetnode
        self._future = future
        self._loop = targetnode._loop
        self._ipaddr = targetnode._last_address
        self._rq_id = uuid.uuid4()
        self._log = targetnode._log.getChild(
            "%s:%s" % (self.__class__.__name__, self._rq_id)
        )

        self._timeout = None

    @property
    def rq_id(self):
        """
        Return the request ID.
        """
        return self._rq_id

    def start(self):
        """
        Start the operation (and the time-out timer!)
        """
        # Register ourselves
        self._log.debug("Request registered")
        self._targetnode._operations[self.rq_id] = self

        # Start the timer
        self._log.debug("Time-out timer started")
        self._timeout = self._loop.call_later(OP_TIMEOUT, self._on_timeout)

        # Fire off asynchronous tasks
        asyncio.create_task(self._asyncstart())

    def _on_recv(self, addr, kid, outermsg, msg):
        """
        Process a message from the node relating to this request.
        """
        self._log.debug("Received %s", msg)

    @property
    def _privkey(self):
        """
        Return the private key need to sign Sign1 messages sent to the remote
        node.
        """
        return self._ownnode._node_keypair.privkey

    def _cleanup(self):
        """
        Stop timers and de-register.
        """
        if self._timeout is not None:
            self._log.debug("Time-out timer stopped")
            self._timeout.cancel()
            self._timeout = None

        if self._targetnode._operations.get(self.rq_id) is self:
            self._log.debug("Request de-registered")
            self._targetnode._operations.pop(self.rq_id, None)

    def _on_timeout(self):
        """
        Process an operation time-out.
        """
        self._log.debug("Time-out timer expired")
        self._timeout = None
        self._log.info("Operation timed out")
        self._on_failure(IOError("Operation Timed out"))

    def _on_failure(self, exc):
        """
        Handle an operation failure.
        """
        self._cleanup()
        if self._future.done():
            self._log.debug("Exception %s after future was done", exc)
        else:
            self._log.warning("Operation fails with exception %s", exc)
            self._future.set_exception(exc)

    def _finish(self, result=None):
        """
        Signal operation success.
        """
        self._cleanup()
        if self._future.done():
            self._log.debug("Result after future was done")
        else:
            self._log.info("Operation complete")
            self._future.set_result(result)


class NodeOneShotOp(NodeOpBase):
    """
    Asynchronously request something from a node.
    """

    # By default, these should be encrypted
    ENCRYPTED = True

    def __init__(self, ownnode, targetnode, future, **kwargs):
        super().__init__(self, ownnode, targetnode, future)
        self._kwargs = kwargs

    @property
    def _encrypt(self):
        return self.ENCRYPTED

    @property
    def _rq_msg(self):
        return self.REQUEST_MSG_CLASS(rq_id=self.rq_id, **self._kwargs)

    async def _asyncstart(self):
        try:
            symkey = self._targetnode.o2o_key
            if self._encrypt and (symkey is None):
                self._log.info(
                    "Operation requires shared one-to-one key, requesting "
                    "negotiation"
                )
                symkey = await self._targetnode._negotiate_o2o_key()

            # Submit the request
            msg = self._rq_msg
            self._log.debug(
                "Sending %s request %s",
                msg.__class__.__name__,
                (
                    ("encrypted with key %s" % symkey.kid)
                    if symkey
                    else "unencrypted"
                ),
            )
            self._ownnode._send_msg(
                msg, self._targetnode._last_address, symkey=symkey
            )
        except Exception as ex:
            # Catch exceptions
            self._log.exception("Failed one-shot operation")
            self._on_failure(ex)

    def _on_recv(self, addr, kid, outermsg, msg):
        super()._on_recv(addr, kid, outermsg, msg)

        try:
            if isinstance(msg, NodeRequestRefusalNotification):
                raise msg.as_exc()

            if not self._check_response(addr, kid, outermsg, msg):
                self._ownnode._send_msg(
                    NodeRequestRefusalNotification.from_exc(
                        TypeError(
                            "Unexpected message type: %s"
                            % msg.__class__.__name__
                        )
                    ),
                    addr,
                    symkey=None,
                )
        except Exception as ex:
            # Catch exceptions
            self._log.exception("One-shot operation fails")
            self._on_failure(ex)

    def _check_response(self, addr, kid, outermsg, msg):
        """
        Check if this is the sort of message we expected.
        """
        return isinstance(msg, self.EXPECTED_MSG_CLASS)

    def _process_response(self, addr, kid, outermsg, msg):
        """
        Process the resultant message.
        """
        self._finish(msg)


class NodeMultiShotOp(NodeOpBase):
    """
    Asynchronously fetch something from a node that requires multiple requests
    """

    # How long we wait before sending the next batch?
    FOLLOWUP_DELAY = 5.0

    # By default, require encrypted comms
    ENCRYPTED = True

    def __init__(self, ownnode, targetnode, future, **kwargs):
        super().__init__(self, ownnode, targetnode, future)
        self._kwargs = kwargs
        self._followup_timeout = None

    @property
    def _encrypt(self):
        return self.ENCRYPTED

    @property
    def _rq_msg(self):
        return self.REQUEST_MSG_CLASS(rq_id=self.rq_id, **self._kwargs)

    async def _asyncstart(self):
        await self._send_next()

    async def _send_next(self, addr=None):
        try:
            self._cancel_followup()

            # Perform checks to see what is needed
            await self._check_if_done()

            # If we're done, finish up
            if self._is_done:
                # Nothing more to do
                self._finish()
                return

            symkey = self._targetnode.o2o_key
            if self._encrypt and (symkey is None):
                self._log.info(
                    "Operation requires shared one-to-one key, requesting "
                    "negotiation"
                )
                symkey = await self._targetnode._negotiate_o2o_key()

            # Submit the next part of the request
            msg = self._rq_msg
            self._log.debug(
                "Sending %s request %s",
                msg.__class__.__name__,
                (
                    ("encrypted with key %s" % symkey.kid)
                    if symkey
                    else "unencrypted"
                ),
            )
            self._ownnode._send_msg(
                msg, addr or self._targetnode._last_address, symkey=symkey
            )
        except Exception as ex:
            # Catch exceptions
            self._log.exception("Failed one-shot operation")
            self._on_failure(ex)

    def _on_recv(self, addr, kid, outermsg, msg):
        super()._on_recv(addr, kid, outermsg, msg)

        try:
            # Stop the follow-up timer
            self._cancel_followup()

            if isinstance(msg, NodeRequestRefusalNotification):
                raise msg.as_exc()

            asyncio.create_task(self._asyncrecv(addr, kid, outermsg, msg))
        except Exception as ex:
            # Catch exceptions
            self._log.exception("Failed to process CA certificates")
            self._on_failure(ex)

    async def _asyncrecv(self, addr, kid, outermsg, msg):
        try:
            expected_type = await self._check_response(
                addr, kid, outermsg, msg
            )
            if not expected_type:
                self._ownnode._send_msg(
                    NodeRequestRefusalNotification.from_exc(
                        TypeError(
                            "Unexpected message type: %s"
                            % msg.__class__.__name__
                        )
                    ),
                    addr,
                    symkey=None,
                )
            try:
                await self._process_response(addr, kid, outermsg, msg)

                await self._check_if_done()
                if self._is_done:
                    self._log.info("Operation complete")
                    self._finish()
                else:
                    self._log.info("More to come")
                    self._schedule_followup()
            except Exception as ex:
                # Notify the sender
                self._ownnode._send_msg(
                    NodeRequestRefusalNotification.from_exc(ex),
                    addr,
                    symkey=None,
                )
                raise
        except Exception as ex:
            # Catch exceptions
            self._log.exception("Failed to process CA certificates")
            self._on_failure(ex)

    async def _check_response(self, addr, kid, outermsg, msg):
        """
        Check if this is the sort of message we expected.
        """
        return isinstance(msg, self.EXPECTED_MSG_CLASS)

    def _schedule_followup(self):
        self._followup_timeout = self._loop.send_later(
            self.FOLLOWUP_DELAY, self._on_followup
        )

    def _cancel_followup(self):
        if self._followup_timeout is None:
            self._followup_timeout.cancel()
            self._followup_timeout = None

    def _on_followup(self):
        self._log.info("Sending follow-up request")
        self._followup_timeout = None
        self._send_next()

    def _cleanup(self):
        self._cancel_followup()
        super()._cleanup()


class NodeFetchIdentityOp(NodeOneShotOp):
    """
    Asynchronously fetch the identity of a node.
    """

    REQUEST_MSG_CLASS = NodeMsgIDSolicitation
    EXPECTED_MSG_CLASS = NodeMsgIDNotification
    ENCRYPTED = False

    def __init__(self, ownnode, targetnode, future, **kwargs):
        super().__init__(
            self,
            ownnode,
            targetnode,
            future,
            name=self._ownnode.name,
            kid=self._ownnode.node_kid,
            cert=self._ownnode.node_cert,
            usertoken=self._ownnode.usertoken,
            ca_keyids=self._ownnode.ca_keyids,
        )


class NodeFetchCACertsOp(NodeMultiShotOp):
    """
    Asynchronously fetch the given CA certificates.
    """

    # Don't require encryption
    ENCRYPTED = False

    REQUEST_MSG_CLASS = NodeMsgCASolicitation
    EXPECTED_MSG_CLASS = NodeMsgCANotification

    def __init__(self, ca_kids, ownnode, targetnode, future):
        super().__init__(self, ownnode, targetnode, future)
        self._ca_kids = set(ca_kids)
        self._todo = self._ca_kids.copy()
        self._unavailable_cas = set()
        self._candidate_cas = targetnode._candidate_cas

    @property
    def _rq_msg(self):
        return self.REQUEST_MSG_CLASS(keylist=self._todo, rq_id=self.rq_id)

    def _finish(self):
        """
        Finish up the request, send back the requested keys
        """
        self._log.info("No more CAs left to fetch")
        if self._unavailable_cas:
            # CAs were unavailable
            self._on_failure(
                ValueError(
                    "CAs could not be fetched: %s"
                    % ", ".join(str(kid) for kid in self._unavailable_cas)
                )
            )
        else:
            # Got 'em all.
            super()._finish(
                dict(
                    [(kid, self._candidate_cas[kid]) for kid in self._ca_kids]
                )
            )

    async def _check_if_done(self):
        # Remove from the list any CAs that have been retrieved elsewhere
        self._todo -= set(self._candidate_cas.keys())

    @property
    def _is_done(self):
        return not self._todo

    async def _process_response(self, addr, kid, outermsg, msg):
        for kid, cert in msg.items():
            self._log.debug("Received %s: %s", kid, cert)
            if cert is not None:
                self._candidate_cas[kid] = cert
            else:
                self._unavailable_cas.add(kid)
            self._todo.discard(kid)


class NodeFetchSenderKeysOp(NodeMultiShotOp):
    """
    Asynchronously fetch sender keys.
    """

    # Require this be encrypted!!!
    ENCRYPTED = True

    REQUEST_MSG_CLASS = NodeMsgSenderKeySolicitation
    EXPECTED_MSG_CLASS = NodeMsgSenderKeyNotification

    def __init__(self, sender_kids, ownnode, targetnode, future):
        super().__init__(self, ownnode, targetnode, future)
        self._sender_kids = set(sender_kids)
        self._todo = self._sender_kids.copy()
        self._unavailable_kids = set()
        self._fetched = {}

    @property
    def _rq_msg(self):
        return self.REQUEST_MSG_CLASS(keylist=self._todo, rq_id=self.rq_id)

    async def _check_if_done(self):
        # Remove from the list any keys that have been retrieved
        self._todo -= set(self._fetched.keys())

    @property
    def _is_done(self):
        return not self._todo

    def _finish(self):
        """
        Finish up the request, send back the requested keys
        """
        self._log.info("No more keys left to fetch")
        if self._unavailable_kids:
            # keys were unavailable
            self._on_failure(
                ValueError(
                    "Sender keys could not be fetched: %s"
                    % ", ".join(str(kid) for kid in self._unavailable_kids)
                )
            )
        else:
            # Got 'em all.
            super()._finish(self._fetched)

    async def _process_response(self, addr, kid, outermsg, msg):
        for kid, cert in msg.items():
            self._log.debug("Received %s: %s", kid, cert)
            if cert is not None:
                self._candidate_cas[kid] = cert
            else:
                self._unavailable_kids.add(kid)
            self._todo.discard(kid)


class NodeInitiateSharedKeyOp(NodeOpBase):
    """
    Negotiate a shared secret using X25519 ECDHE -- initiating end.
    """

    # Inherited defaults
    NONCE_SZ = NodeMsgPeerKeyNotification.NONCE_SZ
    DERIVED_KEY_SZ = NodeMsgPeerKeyNotification.DERIVED_KEY_SZ
    HASH_ALGO = NodeMsgPeerKeyNotification.HASH_ALGO
    SALT_SZ = NodeMsgPeerKeyNotification.SALT_SZ
    INFO_SZ = NodeMsgPeerKeyNotification.INFO_SZ

    def __init__(self, ownnode, targetnode, future):
        super().__init__(self, ownnode, targetnode, future)
        self._ecdhe_priv = None  # Our private X25519 key
        self._ecdhe_derived = None  # The derived key
        self._cose_key = None  # Generated COSE key
        self._kid = None  # The KID we decided for this new key
        self._nonce = None  # Our nonce for the peer

    def start(self):
        super().start()

        # Generate our X25519 key pair
        self._ecdhe_priv = SafeX25519PrivateKey.generate()
        pubkey = self._ecdhe_priv.public
        self._log.debug("Generated private key: %s", self._ecdhe_priv)

        # Send it to the peer.
        self._ownnode._send_msg(
            NodeMsgPeerKeySolicitation(
                rq_id=self.rq_id,
                pubkey=pubkey,
            ),
            self._targetnode._last_address,
            symkey=None,
        )
        self._log.debug("Sent public key: %s", pubkey)

    def _on_recv_pkn(self, addr, msg):
        # Peer has accepted
        # TODO: sanity check what we are given against node policy!
        # For now, assume it matches what we have.
        self._log.debug(
            "Peer accepted key negotiation request, parameters: "
            "Key size=%d, Algorithm=%s, Salt=%d, Info=%d, Nonce=%d",
            msg.keysize,
            msg.algorithm,
            len(msg.salt),
            len(msg.info),
            len(msg.nonce),
        )
        assert (
            msg.keysize >= self.DERIVED_KEY_SZ
        ), "Derived key size too small"
        assert msg.algorithm != self.HASH_ALGO, "Unacceptable algorithm"
        assert len(msg.salt) >= self.SALT_SZ, "Salt length too short"
        assert len(msg.info) >= self.INFO_SZ, "Information length too short"
        assert len(msg.nonce) >= self.NONCE_SZ, "Nonce length too short"

        # Derive our key with the values they gave us.
        self._ecdhe_derived = self._ecdhe_priv.exchange_and_derive(
            msg.pubkey,
            derived_key_sz=msg.keysize,
            salt=msg.salt,
            info=msg.info,
            algorithm=msg.algorithm,
        )
        self._log.debug("Derived shared key: %s", self._ecdhe_derived)

        # Create a COSE key
        self._cose_key = self._ecdhe_derived.as_cose_key(
            MacCreateOp, MacVerifyOp, EncryptOp, DecryptOp
        )

        # Figure out the key ID we'll use to identify it henceforth.
        self._kid = KeyID(
            owner_uuid=self._ownnode.node_uuid,
            purpose=KeyPurpose.UNICAST,
            fingerprint=self._cose_key.ident,
        )

        # Generate a verification MAC0
        verification = self._cose_key.generate_mac0(
            msg.nonce, kid=bytes(self._kid)
        )
        self._log.debug("Generated verification: %s", verification.hex())

        # Send it to the peer.
        reply = NodeMsgPeerKeyVerificationSolicitation(
            rq_id=self.rq_id,
            verification=verification,
            # Ensure our nonce is as big as theirs
            nonce_sz=len(msg.nonce),
        )
        self._ownnode._send_msg(reply, addr, symkey=None)

        # Save our nonce
        self._nonce = reply.nonce

    def _on_recv_pkvn(self, addr, msg):
        self._log.debug(
            "Peer accepted key validation request, parameters: "
            "Validation=%s, Nonce=%d",
            msg.validation.hex(),
            len(msg.nonce),
        )

        # Validate the MAC0
        mac0 = self._cose_key.validate_mac0(msg.verification)
        self._log.debug(
            "Expecting %s, got %s", self._nonce.hex(), mac0.payload.hex()
        )
        if mac0.payload != self._nonce:
            raise ValueError("Invalid nonce")

        # We're good
        self._log.info("Negotiated shared key: %s", self._cose_key)

        # Wrap the key for future use
        key = NodeSharedKey(kid=self._kid, key=self._cose_key)
        self._finish(key)

    def _on_recv(self, addr, kid, outermsg, msg):
        super()._on_recv(addr, kid, outermsg, msg)

        try:
            if isinstance(msg, NodeRequestRefusalNotification):
                raise msg.as_exc()

            try:
                if isinstance(msg, NodeMsgPeerKeyNotification):
                    self._on_recv_pkn(addr, msg)
                elif isinstance(msg, NodeMsgPeerKeyVerificationNotification):
                    self._on_recv_pkn(addr, msg)
                else:
                    raise TypeError(
                        "Unexpected message type: %s" % msg.__class__.__name__
                    )
            except Exception as ex:
                # Notify the sender
                self._ownnode._send_msg(
                    NodeRequestRefusalNotification.from_exc(ex),
                    addr,
                    symkey=None,
                )
                raise
        except Exception as ex:
            # Catch exceptions
            self._log.exception("Failed to perform ECDHE")
            self._on_failure(ex)


class NodeRespondSharedKeyOp(NodeOpBase):
    """
    Negotiate a shared secret using X25519 ECDHE -- responding end.
    """

    # Inherited defaults
    NONCE_SZ = NodeMsgPeerKeyNotification.NONCE_SZ
    DERIVED_KEY_SZ = NodeMsgPeerKeyNotification.DERIVED_KEY_SZ
    HASH_ALGO = NodeMsgPeerKeyNotification.HASH_ALGO
    SALT_SZ = NodeMsgPeerKeyNotification.SALT_SZ
    INFO_SZ = NodeMsgPeerKeyNotification.INFO_SZ

    def __init__(self, pubkey, ownnode, targetnode, future):
        super().__init__(self, ownnode, targetnode, future)
        self._ecdhe_pub = pubkey  # Their public X25519 key
        self._ecdhe_priv = None  # Our private X25519 key
        self._ecdhe_params = None  # Our ECDHE parameters
        self._ecdhe_derived = None  # The derived key
        self._cose_key = None  # Generated COSE key
        self._kid = None  # The KID we decided for this new key

    def start(self):
        super().start()

        # Generate our X25519 key pair
        self._ecdhe_priv = SafeX25519PrivateKey.generate()
        pubkey = self._ecdhe_priv.public
        self._log.debug("Generated private key: %s", self._ecdhe_priv)

        # Send it to the peer.
        self._ecdhe_params = NodeMsgPeerKeyNotification(
            rq_id=self.rq_id,
            pubkey=pubkey,
            keysize=self.DERIVED_KEY_SZ,
            algorithm=self.HASH_ALGO,
            salt_sz=self.SALT_SZ,
            info_sz=self.INFO_SZ,
            nonce_sz=self.NONCE_SZ,
        )
        self._ownnode._send_msg(
            self._ecdhe_params,
            self._targetnode._last_address,
            symkey=None,
        )
        self._log.debug("Sent public key, parameters and nonce: %s", pubkey)

    def _on_recv_pkvs(self, addr, msg):
        # Peer has accepted
        self._log.debug("Peer accepted key negotiation parameters")

        # Derive our key with the parameters we agreed upon.
        self._ecdhe_derived = self._ecdhe_priv.exchange_and_derive(
            self._ecdhe_pub,
            derived_key_sz=self._ecdhe_params.keysize,
            salt=self._ecdhe_params.salt,
            info=self._ecdhe_params.info,
            algorithm=self._ecdhe_params.algorithm,
        )
        self._log.debug("Derived shared key: %s", self._ecdhe_derived)

        # Create a COSE key
        self._cose_key = self._ecdhe_derived.as_cose_key(
            MacCreateOp, MacVerifyOp, EncryptOp, DecryptOp
        )

        # Validate the MAC0 they sent us
        mac0 = self._cose_key.validate_mac0(msg.verification)
        self._log.debug(
            "Expecting %s, got %s",
            self._ecdhe_params.nonce.hex(),
            mac0.payload.hex(),
        )
        if mac0.payload != self._ecdhe_params.nonce:
            raise ValueError("Invalid nonce")

        # Use the KID they came up with.
        self._kid = KeyID.decode(mac0.uhdr[KID])

        # Generate a verification MAC0
        verification = self._cose_key.generate_mac0(
            msg.nonce, kid=bytes(self._kid)
        )
        self._log.debug("Generated verification: %s", verification.hex())

        # Send it to the peer.
        self._ownnode._send_msg(
            NodeMsgPeerKeyVerificationNotification(
                rq_id=self.rq_id,
                verification=verification,
            ),
            addr,
            symkey=None,
        )

        # We're good
        self._log.info("Negotiated shared key: %s", self._cose_key)

        # Wrap the key for future use
        key = NodeSharedKey(kid=self._kid, key=self._cose_key)
        self._finish(key)

    def _on_recv(self, addr, kid, outermsg, msg):
        super()._on_recv(addr, kid, outermsg, msg)

        try:
            if isinstance(msg, NodeRequestRefusalNotification):
                raise msg.as_exc()

            try:
                if isinstance(msg, NodeMsgPeerKeyVerificationSolicitation):
                    self._on_recv_pkvs(addr, msg)
                else:
                    raise TypeError(
                        "Unexpected message type: %s" % msg.__class__.__name__
                    )
            except Exception as ex:
                # Notify the sender
                self._ownnode._send_msg(
                    NodeRequestRefusalNotification.from_exc(ex),
                    addr,
                    symkey=None,
                )
                raise
        except Exception as ex:
            # Catch exceptions and clean up request
            self._log.exception("Failed to perform ECDHE")
            self._on_failure(ex)


class NodeFetchSubscriptionsOp(NodeOneShotOp):
    """
    Asynchronously fetch the MAC listener subscriptions of a node.
    """

    REQUEST_MSG_CLASS = NodeMsgMACListenerSolicitation
    EXPECTED_MSG_CLASS = NodeMsgMACListenerNotification

    def __init__(self, maclist, ownnode, targetnode, future, vlan=None):
        super().__init__(
            self, ownnode, targetnode, future, maclist=maclist, vlan=vlan
        )
