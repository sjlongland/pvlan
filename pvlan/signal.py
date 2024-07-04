#!/usr/bin/env python3

"""
Signal emitter interface.
"""

# © 2024 Stuart Longland
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio


class Signal(object):
    """
    Synchronous signal dispatcher.
    """

    def __init__(self):
        self._listeners = {}
        self._idx = 0

    def connect(self, listener, *args, **kwargs):
        """
        Connect a listener to this signal.
        """
        idx = self._idx
        self._idx += 1
        self._listeners[idx] = (listener, args, kwargs)
        return idx

    def disconnect(self, listener):
        """
        Disconnect a listener from this signal.
        """
        if callable(listener):
            # Disconnect by listening function
            matches = set()
            for idx, (l, _, _) in self._listeners():
                if l is listener:
                    matches.add(idx)
        elif isinstance(listener, int):
            # Disconnect by index
            matches = (listener,)

        for idx in matches:
            self._listeners.pop(idx, None)

    def emit(self, *args, **kwargs):
        """
        Emit a signal to all listeners.
        """
        listeners = list(self._listeners)
        for listener in listeners:
            self._emit_to(listener, args, kwargs)

    def _emit_to(self, listener, sig_args, sig_kwargs):
        (fn, fn_args, fn_kwargs) = listener

        args = fn_args + sig_args
        kwargs = fn_kwargs.copy()
        kwargs.update(sig_kwargs)

        fn(*args, **kwargs)


class AsyncSignal(Signal):
    """
    Fire-and-forget asynchronous signal dispatcher.
    """

    def __init__(self, loop=None):
        super().__init__()

        if loop is None:
            loop = asyncio.get_event_loop()

        self._loop = loop

    def _emit_to(self, listener, sig_args, sig_kwargs):
        self._loop.call_soon(super()._emit_to, listener, sig_args, sig_kwargs)
