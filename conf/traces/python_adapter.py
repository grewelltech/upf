# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation

"""Drives conf/route_control.py through a trace.

The controller's two threads are never started. Netlink messages go to the
two handlers directly, in trace order, so the ops it issues are
deterministic as far as the controller is (deleting an attached network
iterates a set, so the order of its host-route deletes is not). The ping
loop's own body runs at start, as the real thread's first pass does, and
again whenever its 10 s period has elapsed on the virtual clock: on a tick,
and after an event whose retries slept past the deadline. Its reads of the
kernel come from the fake kernel, its BESS client is the fake, sleeps go to
the virtual clock, and send_ping is recorded as a probe.

route_control imports pyroute2, scapy and pybess at module level. The
harness uses none of them: pyroute2 and scapy only in code the harness
replaces (NDB handler registration, the ICMP probe), and pybess only for its
exception classes. When a library is missing, a stub module with the names
route_control imports stands in, so the traces run with the standard
library alone. The pybess exception classes are always the stub's, patched
into route_control for the run, because the existing unit tests replace
pybess with a MagicMock whose attributes cannot be caught by `except`.
"""

from __future__ import annotations

import errno
import logging
import os
import signal
import sys
import types
from typing import Any
from unittest.mock import patch

from conf.traces.runner import Adapter, FakeBess, FakeKernel, Recorder, VirtualClock


def _stub_module(name: str, **attrs: Any) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


class BESS:
    """The exception classes of pybess.bess.BESS, as route_control catches them."""

    class Error(Exception):
        def __init__(self, code: int, errmsg: str, **kwargs: Any) -> None:
            super().__init__(code, errmsg)
            self.code = code
            self.errmsg = errmsg
            self.info = kwargs

        def __str__(self) -> str:
            name = errno.errorcode.get(self.code, "<unknown>")
            return (
                f"errno={self.code} ({name}: {os.strerror(self.code)}), {self.errmsg}"
            )

    class RPCError(Exception):
        pass

    class APIError(Exception):
        pass

    class ConstraintError(Exception):
        pass


errors = BESS


def _ensure_importable() -> None:
    try:
        import pyroute2
        import pyroute2.netlink.rtnl.ndmsg
        import pyroute2.netlink.rtnl.rtmsg
    except ImportError:
        pyroute2 = _stub_module(
            "pyroute2", NDB=type("NDB", (), {}), IPRoute=type("IPRoute", (), {})
        )
        netlink = _stub_module("pyroute2.netlink")
        rtnl = _stub_module("pyroute2.netlink.rtnl")
        _stub_module("pyroute2.netlink.rtnl.ndmsg", ndmsg=type("ndmsg", (), {}))
        _stub_module("pyroute2.netlink.rtnl.rtmsg", rtmsg=type("rtmsg", (), {}))
        pyroute2.netlink = netlink
        netlink.rtnl = rtnl
    try:
        import scapy.all
    except ImportError:
        scapy = _stub_module("scapy")
        scapy.all = _stub_module(
            "scapy.all",
            ICMP=lambda *a, **k: None,
            IP=lambda *a, **k: None,
            send=lambda *a, **k: None,
        )
    if "pybess.bess" not in sys.modules:
        try:
            import pybess.bess
        except ImportError:
            # route_control uses errno without importing it: the name comes
            # in through `from pybess.bess import *`, which re-exports what
            # pybess/bess.py imports at module level. The stub exports the
            # same standard-library modules so that path behaves the same.
            import pprint
            import re
            import time

            pybess = _stub_module("pybess")
            pybess.bess = _stub_module(
                "pybess.bess",
                BESS=BESS,
                errno=errno,
                os=os,
                pprint=pprint,
                re=re,
                sys=sys,
                time=time,
            )


_ensure_importable()

import conf.route_control as rc


class _Interfaces:
    """ndb.interfaces[index].get("ifname"); the ndb namespace keeps pyroute2 names.

    For an index the kernel does not have, pyroute2's NDB view returns an
    unloaded record whose .get("ifname") is None, so an empty dict is the
    same outcome.
    """

    def __init__(self, kernel: FakeKernel) -> None:
        self._kernel = kernel

    def __getitem__(self, index: Any) -> dict[str, str]:
        name = self._kernel.ifname(index)
        return {"ifname": name} if name else {}


class PythonAdapter(Adapter):
    PING_PERIOD_S = 10  # the sleep in _ping_missing_entries

    def __init__(
        self,
        kernel: FakeKernel,
        bess: FakeBess,
        clock: VirtualClock,
        recorder: Recorder,
        interfaces: list[str],
    ) -> None:
        self._kernel = kernel
        self._bess = bess
        self._recorder = recorder
        self._clock = clock
        self._next_ping = float("inf")  # set by start()
        self._patches: list[Any] = []
        self._logger = logging.getLogger(rc.__name__)
        self._was_disabled = self._logger.disabled

        def ifname(index: Any) -> str:
            name = kernel.ifname(index)
            if name is None:
                raise OSError("no such interface")
            return name

        self._fake_time = fake_time = types.SimpleNamespace(
            sleep=clock.sleep, time=clock.time, monotonic=clock.time
        )
        fake_signal = types.SimpleNamespace(
            pause=lambda: None,
            signal=lambda *a, **k: None,
            SIGHUP=signal.SIGHUP,
            SIGINT=signal.SIGINT,
            SIGTERM=signal.SIGTERM,
        )
        patches = [
            # create=True: when another test module has replaced pybess.bess
            # with a MagicMock before route_control was imported, its star
            # import brought in nothing, so BESS and errno are missing.
            patch.object(rc, "BESS", errors, create=True),
            patch.object(rc, "errno", errno, create=True),
            patch.object(rc.BessController, "_get_bess", lambda self, ip, port: bess),
            patch.object(rc, "if_indextoname", ifname),
            patch.object(rc, "send_ping", lambda ip: recorder.record("probe", ip)),
            patch.object(rc, "time", fake_time),
            patch.object(rc, "signal", fake_signal),
        ]
        try:
            for p in patches:
                p.start()
                self._patches.append(p)
            self._logger.disabled = True
            ndb = types.SimpleNamespace(
                neighbours=types.SimpleNamespace(dump=kernel.neigh_dump),
                interfaces=_Interfaces(kernel),
            )
            ipr = types.SimpleNamespace(
                get_routes=lambda family=None: kernel.route_dump(family)
            )
            self.controller = rc.RouteController(
                rc.BessController("fake", "0"), ndb, ipr, interfaces
            )
        except BaseException:
            self.stop()
            raise

    def start(self) -> None:
        # register_handlers and the netlink thread are skipped: events arrive
        # through deliver(), in trace order. The ping thread's first pass,
        # which start() would run right after the route read, runs here, and
        # the later ones whenever the period has elapsed.
        self.controller.bootstrap_routes()
        self._ping_pass()
        self._next_ping = self._clock.now + self.PING_PERIOD_S
        self._run_due_pings()

    def deliver(self, message: dict[str, Any]) -> None:
        event = message.get("event", "")
        if event.endswith("ROUTE"):
            self.controller._handle_route_event(message)
        elif event.endswith("NEIGH"):
            self.controller._handle_neighbor_event(message)
        else:
            raise ValueError(f"unknown netlink event {event}")
        # The ping thread waits on the controller's lock while a handler
        # runs, and takes its pass as soon as the handler lets go, so a pass
        # whose period elapsed during the handler's retries runs now.
        self._run_due_pings()

    def sighup(self) -> None:
        self.controller.reconfigure(signal.SIGHUP)
        self._run_due_pings()

    def _ping_pass(self) -> None:
        """One pass of the controller's own ping loop.

        _ping_missing_entries never returns, so its sleep is made to raise
        after the pass: the loop body runs as written, and that sleep is not
        recorded, since the loop's pacing is not controller behavior.
        """

        class _EndOfPass(Exception):
            pass

        def sleep_once(_: float) -> None:
            raise _EndOfPass

        real_sleep = self._fake_time.sleep
        self._fake_time.sleep = sleep_once
        try:
            self.controller._ping_missing_entries()
        except _EndOfPass:
            pass
        finally:
            self._fake_time.sleep = real_sleep

    def _run_due_pings(self) -> None:
        while self._clock.now >= self._next_ping:
            self._ping_pass()
            self._next_ping += self.PING_PERIOD_S

    def tick(self, seconds: float) -> None:
        """Advances virtual time and runs the ping passes that fall due.

        The deadline of the next pass is kept across ticks, so two ticks of
        5 s run the same pass one tick of 10 s does.
        """
        self._clock.advance(seconds)
        self._run_due_pings()

    def stop(self) -> None:
        self._logger.disabled = self._was_disabled
        for p in reversed(self._patches):
            p.stop()
        self._patches = []
