#!/usr/bin/env python3

"""
PVLAN Node handler
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import asyncio
import socket
import uuid
import time
import enum
import os
import os.path
import weakref

from collections import namedtuple

from pycose.keys.keyops import EncryptOp, DecryptOp

from .key import (
    KeyID,
    Keypair,
    CertificateStore,
    KeyPurpose,
    SafeCOSESymmetricKey,
)
from .mac import MACSubscription
from .multicast import MulticastIPv6Socket
from .msg import (
    NodeSharedKey,
    MissingKeyError,
    IncomingNodeMsg,
    OutgoingNodeMsg,
    NodeMsgType,
    NodeEthernetTrafficNotification,
    NodeMsgIDNotification,
    NodeMsgCANotification,
)
from .ops import (
    NodeFetchCACertsOp,
    NodeFetchIdentityOp,
    NodeFetchSenderKeyOp,
    NodeInitiateSharedKeyOp,
    NodeRespondSharedKeyOp,
)

# Experimental multicast address and port
GROUP_ADDR = "ff02::114"
GROUP_PORT = 48480
GROUP_MTU = 1280

# Expiry in seconds
PEER_EXPIRY = 14400  # 4 hours for peer nodes
MAC_EXPIRY = 300  # 5 minutes for MAC addresses


# VLAN tagged MAC address
class VLANTaggedMAC(namedtuple("_VLANTaggedMAC", ["vlan", "mac"])):
    # VLAN ID representing an untagged frame
    UNTAGGED_VLAN = -1

    @property
    def is_tagged(self):
        return self.vlan == self.UNTAGGED_VLAN

    def __str__(self):
        if self.is_tagged:
            return "VLAN%04d[%s]" % (self.vlan, self.mac)
        else:
            return "UNTAGGED[%s]" % (self.mac,)


class PeerState(enum.ENUM):
    """
    Status of the peer.  Peers go through the following states:

    - UNIDENTIFIED: We've only just learned of this peer, and don't even have
      a peer certificate for it yet.
    - UNVERIFIED: We've learned their identity, but haven't validated it yet.
      We need some CA certificates to check this.
    - VALIDATED: The node is indeed who they say they are.  Authentication
      token not yet checked.
    - AUTHENTICATED: Node and user have been checked.  No symmetric keys
      negotiated yet.
    - CONNECTED: Peer-to-peer link established.  We have exchanged a
      one-to-one symmetric key, and can pass sender keys between us.
    - DISPUTED: Multiple peers are claiming this UUID.  One is an imposter!
    """

    UNIDENTIFIED = 0
    DISPUTED = 1
    UNVERIFIED = 2
    VALIDATED = 10
    AUTHENTICATED = 20
    CONNECTED = 30


class BaseNode(object):
    """
    Node base class implementation.  This implements common logic between
    the node representing this node in the network, and other neighbouring
    nodes.
    """

    def __init__(self, name, node_uuid, mac_expiry, loop=None, log=None):
        self._name = name
        self._node_uuid = node_uuid

        if loop is None:
            loop = asyncio.get_event_loop()

        self._loop = loop
        self._log = logging.getLogger(
            "%s.%s", self.__class__.__module__, self.name
        )

        # Symmetric keys we've negotiated with this node
        self._symkeys = {}

        # Currently chosen keys for the specified purpose
        self._chosen_symkeys = weakref.WeakValueDictionary()

        # The user token for the user at this node
        self._usertoken = None

        # Own learned MAC addresses and the path cost
        # Key: VLANTaggedMAC instance
        # Value: MACSubscription
        self._macsources = {}

        # Recent MAC subscription changes not yet reported
        self._macsub_changed = {}

    @property
    def name(self):
        """
        Return the human-readable name of the node.  Returns
        "noident-${UUID}" if the node is not yet identified.
        """
        if self._name:
            return self._name
        return "noident-%s" % self._node_uuid

    @property
    def node_uuid(self):
        return self._node_uuid

    @property
    def usertoken(self):
        return self._usertoken

    @property
    def _o2o_data_key(self):
        """
        Return the oldest available key intended for unicast data traffic.
        Generates a new one if none is available.
        """
        return self._find_key(KeyPurpose.UNICAST_DATA, generate=True)

    @property
    def _o2m_key(self):
        """
        Return the oldest available key intended for one-to-many control
        traffic.  Generates a new one if none is available.
        """
        return self._find_key(KeyPurpose.MULTICAST, generate=True)

    @property
    def _o2m_data_key(self):
        """
        Return the oldest available key intended for one-to-many data
        traffic.  Generates a new one if none is available.
        """
        return self._find_key(KeyPurpose.MULTICAST, generate=True)

    def _clean_keys(self):
        """
        Check for expired keys and remove them from the keystore.
        """
        expired = set()
        for k in list(self._symkeys.values()):
            if k.is_expired:
                expired.add(k.key_id)

        for key_id in expired:
            self._symkeys.pop(key_id)

    def _find_key(self, purpose, generate=False):
        """
        Return the oldest available symmetric key for the given purpose.
        """
        # Is there one already chosen?
        candidate = self._chosen_symkeys[purpose]

        if (candidate is not None) and candidate.is_expired:
            # Drop the key, it is no longer valid
            candidate = None
            # Do a clean-up to remove other expired keys
            self._clean_keys()

        if candidate is None:
            # Look through all the keys
            for k in self._symkeys.values():
                if k.is_expired:
                    continue

                if k.purpose != purpose:
                    continue

                if (candidate is None) or (candidate.expiry > k.expiry):
                    # Try this one
                    candidate = k

            if (candidate is None) and generate:
                # No key, generate one for this purpose now.
                candidate = self._generate_symkey(purpose)

        if candidate is not None:
            # Stash it for later
            self._chosen_symkeys[purpose] = candidate

        return candidate

    def _validate_usertoken(self, usertoken):
        """
        Validate the user token presented.
        """
        # TODO
        raise NotImplementedError("Not yet implemented")

    def _generate_symkey(self, purpose):
        """
        Generate a key with the given purpose.
        """
        cose_key = SafeCOSESymmetricKey.generate(
            SafeCOSESymmetricKey.KEY_LENGTH_256, EncryptOp, DecryptOp
        )
        kid = KeyID(
            # We are generating the key for them!  So it's our key we
            # share with them, not their key being shard with us.
            owner_uuid=self._ownnode.node_uuid,
            purpose=purpose,
            fingerprint=cose_key.ident,
        )
        key = NodeSharedKey(kid=kid, key=cose_key)
        self._symkeys[kid] = key

        return key

    @property
    def _expired_macsubs(self):
        """
        Return the expired MAC subscriptions
        """
        expired = {}

        for vlanmac, sub in self._macsources.items():
            if sub.is_expired:
                expired[vlanmac] = sub

        return expired

    def _update_mac_sub(self, vlanmac, sub=None, lifetime=None, cost=None):
        """
        Add, replace or remove a MAC subscription to this node.
        """
        if sub is None:
            sub = MACSubscription(lifetime=lifetime, cost=cost)

        # Record the new subscription
        self._macsub_changed[vlanmac] = sub

        if sub.is_expired:
            # Unsubscribe
            self._macsources.pop(vlanmac, None)
        else:
            # Subscribe or update
            self._macsources[vlanmac] = sub

        # Return the subscription
        return sub

    def _clean_macsubs(self):
        """
        Clean up MAC subscriptions.  For the sake of subclasses, return
        the expired MACs.
        """
        expired = self._expired_macsubs

        # Clean up our subscriptions
        for vlanmac in expired.keys():
            self._update_mac_sub(vlanmac, lifetime=0)

        # For subclasses, return the expired subscriptions
        return expired


class PeerNode(BaseNode):
    """
    Peer node class.  This represents _other_ nodes on the virtual network.
    """

    def __init__(self, ownnode, node_uuid, loop):
        super().__init__(name=None, node_uuid=node_uuid, loop=loop)
        self._ownnode = ownnode

        # Node is considered unidentified at first
        self._state = PeerState.UNIDENTIFIED
        self._node_cert = None

        # Candidate identites are used to store (possibly multiple)
        # identites whilst we figure out which one is correct.
        self._candidate_identities = {}

        # Retrieved CA certificates needed to identify the candidate
        # certificates.
        self._candidate_cas = CertificateStore(
            parent=ownnode._certstore_cache
        )

        # In-progress operations currently being processed
        self._operations = {}

        # The address and time this node was last heard from.
        self._last_address = None
        self._last_active = 0

        # Undeciphered traffic.  In the event we have undecipherable traffic
        # we put the messages here for trying again once we have the requisite
        # key to decrypt it.  Keyed by key ID.
        self._undeciphered = {}

    @property
    def state(self):
        return self._state

    @property
    def node_cert(self):
        """
        Return the node's validated public key.
        """
        return self._node_cert

    @property
    def _o2o_key(self):
        """
        Return the oldest available negotiated one-to-one communications key.
        May return ``None`` if no such key has been negotiated.
        """
        # We can't generate it on the spot as we have no way to share it with
        # the peer securely.  We must use ECDHE to negotiate one.
        return self._find_key(KeyPurpose.UNICAST, generate=False)

    @property
    def last_active(self):
        return self._last_active

    @property
    def last_address(self):
        return self._last_address

    def _on_recv(self, incomingmsg):
        """
        Process a message received from this node.
        """
        try:
            msg = incomingmsg.decode(
                cert=self.node_cert, symkeys=self._symkeys
            )
        except MissingKeyError as mke:
            try:
                queue = self._undeciphered[mke.kid]
            except KeyError:
                self._log.info("We are missing key %s", mke.kid)
                queue = []
                self._undeciphered = queue

            queue.append(mke.msg)
            self._log.debug("Queued message for later")
            return

        addr = incomingmsg.addr
        kid = incomingmsg.outer_kid
        self._update_address(addr)

        if self.node_cert is None:
            # Do we have that certificate on hand?
            ident = self._candidate_identities.get(kid)
            if ident is not None:
                # We do, check it's valid
                incomingmsg.validate_outer(ident.cert)

        # Handle incoming solicitations and unsolicited notifications
        if msg.MSG_TYPE in (NodeMsgType.IDS, NodeMsgType.IDN):
            if msg.MSG_TYPE == NodeMsgType.IDS:
                # Node is requesting our identity
                self._send_id_notification(addr, msg)

            # This node has provided us identity information
            asyncio.create_task(self._on_identity_update(incomingmsg))
        elif msg.MSG_TYPE in (NodeMsgType.CAS, NodeMsgType.CAN):
            # This node is requesting or providing CA data
            self._dispatch_rq_msg(incomingmsg)
            if msg.MSG_TYPE == NodeMsgType.CAS:
                # CA request
                self._on_ca_key_solicitation(addr, msg)
        elif self.node_cert is not None:
            # All other message types require a certified identity.
            self._dispatch_rq_msg(incomingmsg)
            if msg.MSG_TYPE == NodeMsgType.ETN:
                # Ethernet traffic
                self._on_ethernet_traffic(addr, msg)
            elif msg.MSG_TYPE == NodeMsgType.PKS:
                # Node is explicitly requesting a shared key negotiation
                asyncio.create_task(
                    self._negotiate_o2o_key(pubkey=msg.pubkey)
                )
            elif msg.MSG_TYPE == NodeMsgType.KEYS:
                # Node is requesting we send them one of our keys
                self._send_sender_keys(*msg, addr=addr, rq_id=msg.rq_id)
            elif msg.MSG_TYPE == NodeMsgType.MLS:
                # Node is requesting we send them our subscriptions
                self._send_subscriptions(
                    msg.vlan, *msg, addr=addr, rq_id=msg.rq_id
                )

    @property
    def _mac_expiry(self):
        return self._ownnode._mac_expiry

    def _send_traffic(self, fragments, addr=None, rq_id=None):
        """
        Send unicast Ethernet traffic direct to this node.
        """
        if addr is None:
            addr = self.last_address

        if rq_id is None:
            rq_id = uuid.uuid4()

        self._send_msg(
            NodeEthernetTrafficNotification(
                fragments=fragments,
                rq_id=rq_id,
                name=self._ownnode.name,
                kid=self._ownnode.node_kid,
                cert=self._ownnode.node_cert,
                usertoken=self._ownnode.usertoken,
                ca_keyids=self._ownnode.ca_keyids,
            ),
            addr,
            symkey=self._o2o_data_key,
        )

    def _send_id_notification(self, addr=None, msg=None):
        """
        Send a node our identity information.
        """
        if addr is None:
            addr = self.last_address

        if msg is None:
            # Unsolicited notification, due to change of user identity.
            rq_id = uuid.uuid4()
        else:
            # Solicited notification
            rq_id = msg._rq_id

        self._log.info(
            "Sending %s identity notification to %s (ID: %s)",
            "solicited" if msg is not None else "unsolicited",
            addr,
            rq_id,
        )
        self._send_msg(
            NodeMsgIDNotification(
                rq_id=msg._rq_id,
                name=self._ownnode.name,
                kid=self._ownnode.node_kid,
                cert=self._ownnode.node_cert,
                usertoken=self._ownnode.usertoken,
                ca_keyids=self._ownnode.ca_keyids,
            ),
            addr,
            # No encryption, as the party requesting likely doesn't have a
            # key shared with us yet.
            symkey=None,
        )

    def _on_ca_key_solicitation(self, addr, msg):
        """
        Handle a request for one or more CA certificates.
        """
        self._send_ca_keys(*msg, addr=addr, rq_id=msg.rq_id)

    def _send_ca_keys(self, *kids, addr=None, rq_id=None):
        """
        Send one or more CA certificates to the node.
        """
        if addr is None:
            addr = self.last_address

        if rq_id is None:
            rq_id = uuid.uuid4()

        # Gather the requested certificates
        certs = dict((kid, self._certstore.get(kid)) for kid in kids)

        # Submit the certs as requested
        self._send_msg(
            NodeMsgCANotification(
                rq_id=rq_id,
                certs=certs,
            ),
            addr,
            # No encryption, as the recipient likely isn't sharing a key with
            # us to be able to decrypt our traffic.
            symkey=None,
        )

    async def _on_identity_update(self, incomingmsg):
        """
        Identity information has been provided by the remote node.
        """
        msg = incomingmsg.msg
        kid = incomingmsg.outer_kid

        # Do we have a public key for this node already?
        if self.node_cert is None:
            # No, does the message at least validate?
            incomingmsg.validate_outer(msg.cert)

            # Do we have the certificate KID in our key store?
            if kid not in self._candidate_identities:
                # This certificate is new
                self._log.debug("Possible certificate: %s", msg.cert)
                self._candidate_identities[kid] = msg
                if len(self._candidate_identities) > 1:
                    self._log.warning(
                        "Multiple certificates discovered for node, "
                        "latest seen for %s: %s",
                        msg.name,
                        msg.cert,
                    )
                    self._update_state(PeerState.DISPUTED)
                else:
                    self._update_state(PeerState.UNVERIFIED)

                # Gather up the keys we need to validate this
                required_keys = (
                    msg.ca_keyids
                    # candidate_cas is a child of the cache and trusted
                    # key store, so will implicitly pull down all keys.
                    # Crucially: revocation lists are passed down too.
                    - set(self._candidate_cas.keys())
                )

                if required_keys:
                    # Fetch these certificates first
                    await self._fetch_ca_certs(*required_keys)

                # We should have everything we need, validate the cert
                if not self._validate_node_ident(kid):
                    # It did not pass
                    return

        # Else: TODO -- nodes might send a new identity if the user auth
        # token changes, but right now we don't even implement that bit.
        # Node certificate should _NOT_ be changing!
        if self.usertoken is not None:
            await self._validate_usertoken(msg.usertoken)

        # User is authenticated
        self._update_state(PeerState.AUTHENTICATED)

        if msg.MSG_TYPE == NodeMsgType.IDN:
            # We requested identification, ensure we have a valid peer key.
            await self._negotiate_o2o_key()

    def _fetch_node_identity(self):
        """
        Query the node for its identity information.
        """
        future = asyncio.Future()
        op = NodeFetchIdentityOp(
            ownnode=self._ownnode,
            targetnode=self,
            future=future,
        )
        op.start()
        return future

    def _fetch_sender_keys(self, *sender_keys):
        """
        Fetch symmetric keys missing from our key store.
        """
        future = asyncio.Future()
        op = NodeFetchSenderKeyOp(
            sender_keys=sender_keys,
            ownnode=self._ownnode,
            targetnode=self,
            future=future,
        )
        op.start()
        return future

    def _fetch_ca_certs(self, *ca_kids):
        """
        Fetch the CA certificates with the given key IDs.
        """
        future = asyncio.Future()
        op = NodeFetchCACertsOp(
            ca_kids=ca_kids,
            ownnode=self._ownnode,
            targetnode=self,
            future=future,
        )
        op.start()
        return future

    def _validate_node_ident(self, cert_kid):
        """
        Check and validate the node identity with the given key ID.
        """
        ident = self._candidate_identities[cert_kid]
        cert = ident.cert

        try:
            node_cas = cert.validate_chain(self._candidate_cas)

            # Success, these are the keys we need!  Last one in the chain
            # is our verified certificate.
            node_cert = node_cas.pop()

            # Inspect the CA certificates, ensure the root is trusted!
            if node_cas[0].kid not in self._ownnode._certstore:
                raise ValueError(
                    "Root cert %s not in trust store" % node_cas[0]
                )

        except:
            self._log.exception(
                "Certificate %s could not be validated", cert_kid
            )
            self._candidate_identities.pop(cert_kid, None)
            remaining = len(self._candidate_identities)
            if remaining > 1:
                # There are many others, remain in DISPUTED state
                self._update_state(PeerState.DISPUTED)
            elif remaining == 1:
                # We've ruled out the others, check this one
                self._update_state(PeerState.UNVERIFIED)
            else:
                # None left
                self._update_state(PeerState.UNIDENTIFIED)
            return False

        for cert in node_cas:
            self._ownnode._cache_cert(cert)

        if self._node_cert is None:
            self._update_state(PeerState.VALIDATED)
            self._candidate_identities.clear()
            self._node_cert = node_cert
            self._name = ident.name
            self._log.info(
                "Identified node as %s (cert %s)", self.name, self.node_cert
            )

            # Create a new logger with the correct identity info
            self._log = logging.getLogger(
                "%s.%s", self.__class__.__module__, self.name
            )

        return True

    async def _negotiate_o2o_key(self, pubkey=None):
        """
        Negotiate a one-to-one shared key with the peer.
        """
        # Sanity check, require the node is identified
        if self.node_cert is None:
            self._log.info("Node is not identified, requesting identity")
            await self._fetch_node_identity()

        if (pubkey is None) and (self._o2o_key is not None):
            self._log.info(
                "Using existing negotiated key %s", self._o2o_key.kid
            )
            return

        future = asyncio.Future()
        if pubkey is None:
            # We are asking the peer to negotiate a key with us
            self._log.info("Initiating shared key negotiation request")
            op = NodeInitiateSharedKeyOp(
                ownnode=self._ownnode,
                targetnode=self,
                future=future,
            )
        else:
            # The peer is asking the us to negotiate a key with them
            self._log.info("Responding to shared key negotiation request")
            op = NodeRespondSharedKeyOp(
                pubkey=pubkey,
                ownnode=self._ownnode,
                targetnode=self,
                future=future,
            )
        op.start()

        # Obtain the derived key
        key = await future

        # Store this key
        self._log.info("Negotiated shared key (id %s)", key.kid)
        self._symkeys[key.kid] = key

        # Return it for use
        return key

    def _update_address(self, addr):
        if self._last_address != addr:
            self._log.debug(
                "Node address change %s → %s", self._last_address, addr
            )
            self._last_address = addr
        self._last_active = time.time()

    def _update_state(self, state):
        if state is not self.state:
            self._log.info(
                "State change %s → %s", self.state.label, state.label
            )
            self._state = state

    def _update_mac_sub(self, vlanmac, sub=None, lifetime=None, cost=None):
        """
        Add, replace or remove a MAC subscription to this node.
        """
        sub = super()._update_mac_sub(
            vlanmac, sub=sub, lifetime=lifetime, cost=cost
        )

        if sub.is_expired:
            # Removal
            destinations = self._ownnode._macdestinations.get(vlanmac)

            if destinations is not None:
                self._log.info("No longer listening for %s", vlanmac)
                destinations.pop(self.node_uuid, None)

            if len(destinations) == 0:
                self._log.info(
                    "Last node listening for %s has unsubscribed", vlanmac
                )
                self._ownnode._macdestinations.pop(vlanmac, None)
        else:
            # Addition/update
            try:
                destinations = self._ownnode._macdestinations[vlanmac]
            except KeyError:
                self._log.info(
                    "First node listening for %s has subscribed", vlanmac
                )
                destinations = weakref.WeakValueDictionary()

            if self.node_uuid not in destinations:
                self._log.info("Now listening for %s", vlanmac)
                destinations[self.node_uuid] = self

        # For subclasses, return the subscription
        return vlanmac


class OwnNode(BaseNode):
    """
    Own node class.  This represents this computer on the virtual network.
    """

    def __init__(
        self,
        node_keypair,
        trusted_cert_dir,
        group_addr=GROUP_ADDR,
        group_port=GROUP_PORT,
        group_mtu=GROUP_MTU,
        cert_cache_dir=None,
        name=None,
        node_uuid=None,
        force_sign=False,
        peer_expiry=PEER_EXPIRY,
        mac_expiry=MAC_EXPIRY,
        loop=None,
    ):
        if name is None:
            name = socket.gethostname()

        if node_uuid is None:
            node_uuid = uuid.uuid4()

        super().__init__(name=name, node_uuid=node_uuid, loop=loop)
        self._peer_expiry = peer_expiry
        self._mac_expiry = mac_expiry

        self._log.debug("Loading certificates from %r", trusted_cert_dir)
        self._certstore = CertificateStore()
        self._certstore.add_dir(trusted_cert_dir)

        self._cert_cache_dir = cert_cache_dir
        self._certstore_cache = CertificateStore(parent=self._certstore)
        if cert_cache_dir is None:
            self._log.debug("Not caching third-party certificates")
            self._certcache = None
        else:
            self._log.debug(
                "Loading cached certificates from %r", cert_cache_dir
            )
            self._certstore_cache.add_dir(cert_cache_dir)

        self._log.debug("Loading keypair from %r", node_keypair)
        self._node_keypair = Keypair.load(node_keypair)

        try:
            self._log.debug("Validating keypair")
            self._node_certpath = self._node_keypair.cert.validate_chain(
                self._certstore
            )
        except:
            self._log.exception(
                "Failed to validate node keypair %r", self._node_keypair
            )
            raise

        # Create a transmission socket
        self._socket = MulticastIPv6Socket(
            on_recv=self._on_recv,
            port=group_port,
            groups=(group_addr,),
            loop=self._loop,
            log=self._log.getChild("socket"),
        )
        self._group_addr = group_addr
        self._group_mtu = group_mtu
        self._peers = {}
        self._ignored_nodes = set()
        self._force_sign = bool(force_sign)

        # Remote MAC address destinations:
        # Key: MAC instance
        # Value: WeakValueDictionary
        #   Child key: Node UUID
        #   Child value: Node
        self._macdestinations = {}

    @property
    def node_kid(self):
        return self.node_cert.get_kid(self._node_uuid)

    @property
    def node_cert(self):
        return self._node_keypair.cert

    @property
    def node_certpath(self):
        return self._node_certpath

    @property
    def ca_keyids(self):
        # Last certificate in the path is the node's own certificate
        return set(c.kid for c in self.node_certpath[:-1])

    def _cache_cert(self, cert):
        if cert.kid in self._certstore:
            self._log.debug(
                "Not caching certificate %s: already in trusted store",
                cert.kid,
            )
        elif cert.kid in self._certstore_cache:
            self._log.debug(
                "Not caching certificate %s: already in cache", cert.kid
            )
        else:
            self._log.debug("Caching certificate %s", cert.kid)
            self._certstore_cache.add(cert)
            if self._cert_cache_dir is not None:
                path = os.path.join(
                    self._cert_cache_dir, str(cert.kid) + cert.FILE_EXTN
                )
                self._log.debug("Caching %s to %s", cert.kid, path)
                cert.save_cert(path)

    def _send_msg(self, msg, *targets, sharedkey=None):
        """
        Encrypt, sign and send the payload for the given message.
        """
        outgoingmsg = OutgoingNodeMsg(msg)
        payload = outgoingmsg.encode(
            privkey=self._node_keypair.privkey,
            kid=self._node_kid,
            sharedkey=sharedkey,
            force_encrypt=self._force_encrypt,
            force_sign=self._force_sign,
        )

        # Sanity check the size
        if len(payload) > self._group_mtu:
            raise ValueError("Message is too big!")

        # Send the message
        self._socket.sendmsgto(payload, *targets)

    def _on_recv(self, addr, payload):
        self._log.debug("Received from %s: %s", addr, payload.hex())

        incomingmsg = IncomingNodeMsg(addr=addr, payload=payload)

        # Run the first decoding step to obtain the KID field.
        incomingmsg.decode_outer()
        kid = incomingmsg.outer_kid

        # If the node is on the ignore list, drop the packet
        if kid.node_uuid in self._ignored_nodes:
            self._log.debug(
                "Dropping message from ignored node %s", kid.node_uuid
            )
            return

        try:
            # Look up the node ID in our list of peers
            node = self._peers[kid.node_uuid]
        except KeyError:
            # We don't have this node, so instantiate the node instance
            self._log.info("Discovered new node %s", kid.node_uuid)
            node = PeerNode(self, kid.node_uuid, loop=self._loop)
            self._peers[kid.node_uuid] = node

        try:
            # Pass the received message to the node handler
            node._on_recv(incomingmsg)
        except:
            self._log.info(
                "Failed to handle message from %s (key %s): %s",
                addr,
                kid,
                payload.hex(),
                exc_info=1,
            )

    def _send_traffic(self, fragments, rq_id=None):
        """
        Send multicast Ethernet traffic from this node.
        """
        if rq_id is None:
            rq_id = uuid.uuid4()

        self._send_msg(
            NodeEthernetTrafficNotification(
                fragments=fragments,
                rq_id=rq_id,
            ),
            self._group_addr,
            symkey=self._o2m_data_key,
        )

    def _clean_peers(self):
        """
        Clean up expired peers.
        """
        expired = set()
        expiry = time.time() - self._peer_expiry

        for node_id, peer in self._peers.items():
            if peer.last_active <= expiry:
                self._log.info(
                    "Peer has expired: %s (%s)", peer.name, node_id
                )
                expired.add(node_id)

        for node_id in expired:
            self._peers.pop(node_id, None)
