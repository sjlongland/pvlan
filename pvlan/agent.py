#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:

"""
6LoWHAM tap device agent interface.

The 6LoWHAM agent can be obtained from
https://github.com/sjlongland/6lowham-tap-agent
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import weakref
import asyncio
import logging

from .signal import AsyncSignal
from .mac import MAC

# Byte definitions
SOH = b"\x01"
STX = b"\x02"
E_STX = b"b"
ETX = b"\x03"
E_ETX = b"c"
EOT = b"\x04"
ACK = b"\x06"
DLE = b"\x10"
E_DLE = b"p"
NAK = b"\x15"
SYN = b"\x16"
FS = b"\x1c"


class SixLowHAMAgent(object):
    """
    Wrapper class for the 6LoWHAM agent.  This provides a Python interface
    for sending and receiving Ethernet frames via the 6LoWHAM Agent.
    """

    def __init__(
        self,
        agent_path=None,
        if_name=None,
        if_mac=None,
        if_mtu=None,
        tx_attempts=3,
        loop=None,
        log=None,
    ):

        if loop is None:
            loop = asyncio.get_event_loop()

        if log is None:
            log = logging.getLogger(self.__class__.__module__)

        # Cast inputs
        if if_mac is not None:
            if_mac = MAC.parse(mac, reserve=True)

        # Interface settings.  Make a note of which ones were supplied
        # to us by the caller in case the agent gets stopped and re-started.
        self._agent_path = agent_path or "6lhagent"
        self._if_name_given = if_name is not None
        self._if_name = if_name
        self._if_mac_given = if_mac is not None
        self._if_mac = if_mac
        self._if_mtu_given = if_mtu is not None
        self._if_mtu = if_mtu
        self._tx_attempts = tx_attempts
        self._loop = loop
        self._log = log

        # Internal state
        self._transport = None
        self._protocol = None
        self._if_idx = None
        self._frame_pending = False
        self._retries = tx_attempts
        self._tx_buffer = []

        # Public Signals
        self.connected = AsyncSignal(loop=loop)
        self.disconnected = AsyncSignal(loop=loop)
        self.receivedframe = AsyncSignal(loop=loop)

    @property
    def if_name(self):
        """
        Return the name of the network interface (e.g. `tap0`)
        """
        return self._if_name

    @property
    def if_mac(self):
        """
        Return the MAC address of the network interface as a byte string.
        """
        return self._if_mac

    @property
    def if_idx(self):
        """
        Return the interface index of the network interface.
        """
        return self._if_idx

    async def start(self):
        """
        Start the TAP device agent.
        """
        if self._transport is not None:
            raise RuntimeError("agent already started")

        args = [self._agent_path]

        if self._if_name_given:
            args += ["-n", self._if_name]
        if self._if_mac_given:
            args += ["-a", str(self._if_mac)]
        if self._if_mtu_given:
            args += ["-m", str(self._if_mtu)]

        if self._log:
            self._log.debug("Starting agent with arguments: %s", args)

        (
            self._transport,
            self._protocol,
        ) = await self._loop.subprocess_exec(
            lambda: SixLowHAMAgentProtocol(self),
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

    def send_ethernet_frame(self, frame):
        """
        Enqueue an Ethernet frame to be transmitted.
        """
        if self._log:
            self._log.debug("Enqueueing frame: %r", frame)

        self._tx_buffer.push(frame)
        if not self._frame_pending:
            self._send_next()

    def stop(self):
        """
        Stop the agent.
        """
        self._send_frame(EOT)

    def _report_frame_error(self, raw_frame):
        """
        Emit a frame error to the log.
        """
        self._log.debug("Dropping malformed frame: %s", raw_frame.hex())

    def _on_receive_frame(self, frame):
        """
        Process a received frame from the protocol instance.
        """
        # Split off the frame type byte
        frametype = frame[0:1]
        framedata = frame[1:]

        if frametype == SOH:
            # Interface information:
            # 6 bytes: MAC address
            # 2 bytes: MTU (big endian)
            # 4 bytes: interface index (big endian)
            # 1 byte: length of name field
            # remainder: name field
            #
            #  0  1  2  3  4  5  6  7  8  9 10 11 12 13…
            # MM MM MM MM MM MM mm mm ii ii ii ii LL NN…

            self._if_mac = MAC.parse(framedata[0:6])
            self._if_mtu = (framedata[6] << 8) | framedata[7]
            self._if_idx = (
                (framedata[8] << 24)
                | (framedata[9] << 16)
                | (framedata[10] << 8)
                | framedata[11]
            )
            self._if_name = framedata[13:][: framedata[12]].decode("US-ASCII")

            self._log.debug(
                "TAP device connected: name %s, MAC %s, MTU: %d bytes",
                self._if_name,
                self._if_mac,
                self._if_mtu,
            )
            self.connected.emit(agent=self)

        elif frametype == FS:
            self._log.debug("Received frame: %s", framedata.hex())
            try:
                # TODO: implement parser
                etherframe = framedata
            except:
                self._log.exception("Failed to parse frame %r", framedata)
                self._send_frame(NAK)
                return

            self.receivedframe.emit(frame=etherframe)

        elif frametype in (ACK, NAK):
            self._on_response(frametype == ACK)

        # Do we ACK or NAK this?
        if frametype in (SOH, FS, SYN):
            self._send_frame(ACK)
        elif frametype not in (ACK, NAK):
            # Don't recognise the frame
            self._send_frame(NAK)

    def _on_response(self, success):
        # Ignore if no frame was sent
        if not self._tx_buffer:
            return

        # Remove successful frames, reset retry counter
        if success:
            self._tx_buffer.pop(0)
            self._retries = self._tx_attempts

        # Reset the frame pending flag
        self._frame_pending = False

        if self._tx_buffer:
            self._send_next()

    def _send_next(self):
        assert not self._frame_pending
        while self._tx_buffer:
            if self._retries <= 0:
                # Too many attempts, dropping frame
                if self._log:
                    self._log.warning(
                        "Dropping frame %r after %d send attempts",
                        self._tx_buffer[0],
                        self._tx_attempts,
                    )
                self._tx_buffer.pop(0)
                self._retries = self._tx_attempts
                continue

            # Try sending this frame
            self._send_frame(FS + bytes(self._tx_buffer[0]))
            self._frame_pending = True
            self._retries -= 1
            return

        # No more to send
        assert len(self._tx_buffer) == 0
        self._frame_pending = False
        self._retries = self._tx_attempts

    def _send_frame(self, frame):
        # Apply byte stuffing
        frame = frame.replace(DLE, DLE + E_DLE)
        frame = frame.replace(STX, DLE + E_STX)
        frame = frame.replace(ETX, DLE + E_ETX)

        # Send to stdin of the process
        self._transport.get_pipe_transport(0).write(STX + frame + ETX)

    def _on_exit(self):
        # Clean up the transport and protocol
        self._transport = None
        self._protocol = None

        # Reset the internal state
        self._tx_buffer = []
        self._frame_pending = False
        self._retries = self._tx_attempts

        # Reset the values for parameters not passed into the constructor
        if not self._if_name_given:
            self._if_name = None
        if not self._if_mac_given:
            self._if_mac = None
        if not self._if_mtu_given:
            self._if_mtu = None


class SixLowHAMAgentProtocol(asyncio.SubprocessProtocol):
    """
    Implements the de-serialisation of agent frames and passes these
    back to the parent SixLowHAMAgent object.
    """

    def __init__(self, agent):
        self._agent = weakref.ref(agent)
        self._log = agent._log.getChild("protocol")
        self._buffer = b""

    def pipe_connection_lost(self, fd, exc):
        pass

    def process_exited(self):
        self._agent._on_exit()

    def pipe_data_received(self, fd, data):
        if self._log.isEnabledFor(logging.DEBUG):
            self._log.debug("Received on FD %d: %s", fd, data.hex())
        # Pull in the data received
        self._buffer += data

        # Process all pending frames
        framestart = self._buffer.find(STX)
        pending = []
        while framestart >= 0:
            frameend = self._buffer.find(ETX, framestart)
            if frameend < 0:
                break

            frame = self._buffer[framestart + 1 : frameend]
            self._buffer = self._buffer[frameend + 1 :]
            pending.append(frame)

        # Decode all frames, discard any that cause issues.
        for raw_frame in pending:
            try:
                decoded_frame = self._process_raw_frame(raw_frame)
            except:
                self._log.debug(
                    "Received mangled frame: %s", raw_frame.hex(), exc_info=1
                )
                self._agent()._report_frame_error(raw_frame)
                continue

            try:
                self._agent()._on_receive_frame(decoded_frame)
            except:
                self._log.debug(
                    "Failed to process frame: %s",
                    decoded_frame.hex(),
                    exc_info=1,
                )
                pass

    def _process_raw_frame(self, rawframe):
        """
        Replace the byte-stuffing sequences and return it.
        """
        frame = rawframe.replace(DLE + E_STX, STX)
        frame = frame.replace(DLE + E_ETX, ETX)
        frame = frame.replace(DLE + E_DLE, DLE)
        return frame
