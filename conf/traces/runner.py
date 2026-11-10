# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation

"""Replayable traces for a route controller.

A trace is a JSON file. Its inputs are kernel facts: routes and neighbors
present at start, then route and neighbor events, a BESS daemon restart, or
a BESS error on cue. Its expected outputs are BESS control calls. Nothing in
a trace names a method of any implementation, so the same file can be run
against the Python controller and against a port.

This module holds the parts that do not depend on the controller: the trace
loader and validator, the fake kernel, the fake BESS client with its model
of the module graph, the virtual clock, the comparison and the record and
fill modes. An adapter (see python_adapter.py) drives one implementation
through them.

Steps
-----
Each step is one input, or one checkpoint. A step may carry a "note".

    {"start": true}                    bootstrap from the kernel tables
    {"route_add": {...}}               RTM_NEWROUTE; dst "a.b.c.d/n", gw, oif,
                                       optional table (254), scope, type.
                                       Replaces a route with the same table
                                       and destination, as `ip route replace`
    {"route_del": {...}}               RTM_DELROUTE for a route the kernel
                                       holds (narrowed by gw and oif if given)
    {"neigh_add": {...}}               RTM_NEWNEIGH; dst, lladdr, ifindex
    {"neigh_change": {...}}            RTM_NEWNEIGH with a new lladdr
    {"neigh_unresolved": {...}}        RTM_NEWNEIGH without a lladdr
    {"neigh_del": {...}}               RTM_DELNEIGH for a neighbor the kernel
                                       holds
    {"bess_restart": true}             the daemon restarts at once with the
                                       base pipeline; the client's channel is
                                       broken until it reconnects
    {"bess_down": true}                the daemon goes away: the channel is
                                       broken and every connect attempt fails
    {"bess_up": true}                  the daemon is back with the base
                                       pipeline; the next connect succeeds
    {"bess_reload": true}              the pipeline script is re-run on the
                                       live daemon: base modules back,
                                       channel intact (what SIGHUP follows)
    {"bess_seed": {...}}               modules/links/routes present in BESS
                                       before the controller starts
    {"bess_error": {"op": ..., "code": "EBUSY", "match": {...}}}
                                       the next matching call fails once;
                                       op is one of the recorded op names
                                       below and match names fields of that
                                       op (see FakeBess.MATCH_FIELDS)
    {"sighup": true}                   the reload signal
    {"tick": seconds}                  advance the virtual clock; timer-driven
                                       work that falls due runs
    {"expect": [...], "ordered": bool, "strict": bool, "allow": [...],
     "max_paused_sleep": seconds}
                                       the ops since the last "expect". By
                                       default the effective ops (below) are
                                       compared ignoring order; "ordered"
                                       compares the sequence; "strict" keeps
                                       pacing, error and read entries; each
                                       op in "allow" may appear once without
                                       being expected, in either mode;
                                       "max_paused_sleep" bounds the seconds
                                       slept while the workers were paused
    {"expect_python": [...], "because": "..."}
                                       what route_control.py does today at
                                       this checkpoint, strict and ordered;
                                       present only where it differs from
                                       "expect", and then "because" says why
    {"expect_state": {...}}            the BESS model after the step:
                                       "modules", "absent", "routes", "links",
                                       "forwarding" (prefix -> dst MAC and
                                       the module reached, or drop/unwired)
    {"expect_state_python": {...}, "because": "..."}
                                       the keys of "expect_state" on which
                                       today's Python differs, in state form

A trace must end with a checkpoint, and ops after the last "expect" are an
error. A "*" in an expected value matches anything.

Ops
---
    ["create_module", name, mclass, arg]
    ["connect", m1, ogate, m2, igate]
    ["disconnect", m1, ogate]
    ["destroy_module", name]
    ["module_command", name, cmd, arg]
    ["pause"], ["resume"], ["reconnect"]
    ["list_modules"], ["get_module_info", name]
                                        reads; ignored unless strict
    ["probe", ip]                       not an RPC: the controller tried to
                                        resolve a next hop
    ["sleep", seconds], ["error", code]  not RPCs: what happened in between

An op followed by an ["error", ...] entry was refused by the daemon. It is
recorded, so a strict block shows it, but it is not effective: a non-strict
"expect" does not count it, so a refused call cannot satisfy an intent.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

MAX_GATES = 8192
DROP_GATE = MAX_GATES  # gate.h: a route to DROP_GATE is dropped inside IPLookup
BAD_ROUTE_GATE = MAX_GATES - 1  # the gate up4.bess wires to the `<if>bad_route` sink
MAX_UPDATE_FIELDS = 16  # Update::kMaxFields

# Entries a non-strict "expect" ignores: pacing, failures, and reads of BESS
# state, which an implementation may do as it pleases.
NON_EFFECTIVE = {"pause", "resume", "sleep", "error", "list_modules", "get_module_info"}

# Op name -> number of elements, for linting the blocks in a trace.
OP_ARITY = {
    "create_module": 4,
    "connect": 5,
    "disconnect": 3,
    "destroy_module": 2,
    "module_command": 4,
    "pause": 1,
    "resume": 1,
    "reconnect": 1,
    "list_modules": 1,
    "get_module_info": 2,
    "probe": 2,
    "sleep": 2,
    "error": 2,
}

INPUT_STEPS = {
    "start",
    "route_add",
    "route_del",
    "neigh_add",
    "neigh_change",
    "neigh_unresolved",
    "neigh_del",
    "bess_restart",
    "bess_down",
    "bess_up",
    "bess_reload",
    "bess_seed",
    "bess_error",
    "sighup",
    "tick",
}
OPS_CHECKPOINT_KEYS = {
    "expect",
    "expect_python",
    "ordered",
    "strict",
    "allow",
    "max_paused_sleep",
    "because",
}
STATE_CHECKPOINT_KEYS = {"expect_state", "expect_state_python", "because"}
STATE_KEYS = {"modules", "absent", "routes", "links", "forwarding"}
FILL_IN = "FILL IN"


# ---------------------------------------------------------------------------
# Recording


class Recorder:
    """The ordered list of ops since the last checkpoint."""

    def __init__(self) -> None:
        self.ops: list[list[Any]] = []
        self.all_ops: list[list[Any]] = []

    def record(self, *op: Any) -> None:
        entry = list(op)
        self.ops.append(entry)
        self.all_ops.append(entry)

    def take(self) -> list[list[Any]]:
        ops, self.ops = self.ops, []
        return ops


class VirtualClock:
    """time.sleep that costs nothing and is recorded."""

    def __init__(self, recorder: Recorder) -> None:
        self.now = 0.0
        self._recorder = recorder

    def sleep(self, seconds: float) -> None:
        self._recorder.record("sleep", seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        """Time passes without the controller asking for it: not recorded."""
        self.now += seconds

    def time(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# Fake kernel


def _split_prefix(prefix: str) -> tuple[str, int, int]:
    """Network address, prefix length and address family of a prefix."""
    network = ipaddress.ip_network(prefix, strict=False)
    family = 2 if network.version == 4 else 10
    return str(network.network_address), network.prefixlen, family


class FakeKernel:
    """Route, neighbor and link tables, and the netlink messages for changes.

    Messages have the shape pyroute2 gives them: a dict with top-level
    fields and an "attrs" list of (name, value) pairs. A change the kernel
    could not make (deleting a route it does not hold) is a scenario error,
    because the kernel would emit no event for it.
    """

    def __init__(self, spec: dict[str, Any]) -> None:
        self.links: dict[int, str] = {
            int(k): v for k, v in spec.get("links", {}).items()
        }
        self.routes: list[dict[str, Any]] = [dict(r) for r in spec.get("routes", [])]
        self.neighbors: list[dict[str, Any]] = [
            dict(n) for n in spec.get("neighbors", [])
        ]

    # -- what the controller reads

    def ifname(self, index: Any) -> str | None:
        try:
            return self.links.get(int(index))
        except (TypeError, ValueError):
            return None

    def route_dump(self, family: int | None = None) -> list[dict[str, Any]]:
        """IPRoute.get_routes(family=...): every table, one family if given."""
        messages = [self.route_msg(r, "RTM_NEWROUTE") for r in self.routes]
        if family is None:
            return messages
        return [m for m in messages if m["family"] == family]

    def neigh_dump(self) -> list[dict[str, Any]]:
        """NDB.neighbours.dump(): every family."""
        return [
            {"dst": n["dst"], "lladdr": n.get("lladdr"), "ifindex": n["ifindex"]}
            for n in self.neighbors
        ]

    # -- message shapes

    @staticmethod
    def route_msg(route: dict[str, Any], event: str) -> dict[str, Any]:
        dst, dst_len, family = _split_prefix(route["dst"])
        attrs: list[tuple[str, Any]] = [("RTA_TABLE", route.get("table", 254))]
        if dst_len:
            attrs.append(("RTA_DST", dst))
        if route.get("gw"):
            attrs.append(("RTA_GATEWAY", route["gw"]))
        if "oif" in route:
            attrs.append(("RTA_OIF", route["oif"]))
        return {
            "family": family,
            "dst_len": dst_len,
            "table": route.get("table", 254),
            "type": route.get("type", 1),
            "scope": route.get("scope", 253 if not route.get("gw") else 0),
            "attrs": attrs,
            "event": event,
        }

    @staticmethod
    def neigh_msg(neigh: dict[str, Any], event: str) -> dict[str, Any]:
        attrs: list[tuple[str, Any]] = [("NDA_DST", neigh["dst"])]
        if neigh.get("lladdr"):
            attrs.append(("NDA_LLADDR", neigh["lladdr"]))
        family = 2 if ipaddress.ip_address(neigh["dst"]).version == 4 else 10
        return {
            "family": family,
            "ifindex": neigh["ifindex"],
            "state": neigh.get("state", 2),
            "attrs": attrs,
            "event": event,
        }

    # -- changes, each returning the message the kernel would emit

    @staticmethod
    def _same_route(a: dict[str, Any], b: dict[str, Any]) -> bool:
        """The kernel's identity of a route: table and destination."""
        return (a.get("table", 254), a["dst"]) == (b.get("table", 254), b["dst"])

    def route_add(self, route: dict[str, Any]) -> dict[str, Any]:
        """`ip route replace`: a route with the same table and destination goes."""
        self.routes = [r for r in self.routes if not self._same_route(r, route)]
        self.routes.append(dict(route))
        return self.route_msg(route, "RTM_NEWROUTE")

    def route_del(self, route: dict[str, Any]) -> dict[str, Any]:
        """`ip route del`: the route in that table, narrowed by gw and oif when given."""

        def is_target(r: dict[str, Any]) -> bool:
            if not self._same_route(r, route):
                return False
            return all(r.get(k) == route[k] for k in ("gw", "oif") if k in route)

        removed = [r for r in self.routes if is_target(r)]
        if not removed:
            raise ValueError(
                f"route_del: the kernel holds no route {route}; it would emit no event"
            )
        self.routes = [r for r in self.routes if not is_target(r)]
        # The kernel reports the route it removed, with all its attributes.
        return self.route_msg(removed[0], "RTM_DELROUTE")

    def neigh_add(self, neigh: dict[str, Any]) -> dict[str, Any]:
        key = (neigh["dst"], neigh["ifindex"])
        self.neighbors = [n for n in self.neighbors if (n["dst"], n["ifindex"]) != key]
        self.neighbors.append(dict(neigh))
        return self.neigh_msg(neigh, "RTM_NEWNEIGH")

    def neigh_del(self, neigh: dict[str, Any]) -> dict[str, Any]:
        key = (neigh["dst"], neigh["ifindex"])
        removed = [n for n in self.neighbors if (n["dst"], n["ifindex"]) == key]
        if not removed:
            raise ValueError(
                f"neigh_del: the kernel holds no neighbor {neigh}; it would emit no event"
            )
        self.neighbors = [n for n in self.neighbors if (n["dst"], n["ifindex"]) != key]
        return self.neigh_msg(removed[0], "RTM_DELNEIGH")


# ---------------------------------------------------------------------------
# Fake BESS


def _update_fields(arg: Any) -> list[dict[str, int]]:
    """The fields of an UpdateArg, as Update::CommandAdd keeps them.

    A value wider than its size is not refused: the daemon's width check
    (update.cc:90-97) shifts the value by (8 - size) bytes first, which
    drops the excess, so the low `size` bytes are what gets written.
    """
    fields = []
    for entry in (arg or {}).get("fields", []):
        size = int(entry.get("size", 0))
        if size < 1 or size > 8:
            raise ValueError("'size' must be 1-8")
        value = int(entry.get("value", 0)) & ((1 << (size * 8)) - 1)
        fields.append(
            {"offset": int(entry.get("offset", 0)), "size": size, "value": value}
        )
    return fields


def _dst_mac_from_fields(fields: list[dict[str, int]]) -> str | None:
    """The destination MAC an Update module stamps.

    Update::ProcessBatch applies every field in order, so the six bytes at
    offsets 0-5 are the result of all the writes that overlap them, in
    order. None until every one of the six has been written.
    """
    octets: list[int | None] = [None] * 6
    for entry in fields:
        for i in range(entry["size"]):
            offset = entry["offset"] + i
            if 0 <= offset < 6:
                shift = (entry["size"] - 1 - i) * 8
                octets[offset] = (entry["value"] >> shift) & 0xFF
    if any(o is None for o in octets):
        return None
    return ":".join(f"{o:02x}" for o in octets)


def _mac_from_update_arg(arg: Any) -> str | None:
    try:
        return _dst_mac_from_fields(_update_fields(arg))
    except (ValueError, TypeError, AttributeError):
        return None


def _decode_module_arg(mclass: str, arg: Any) -> Any:
    if mclass == "Update":
        mac = _mac_from_update_arg(arg)
        if mac:
            return {"dst_mac": mac}
    return arg


@dataclass
class FakeModule:
    mclass: str
    arg: Any = None
    ogates: dict[int, tuple[str, int]] = field(default_factory=dict)
    routes: dict[tuple[str, int], int] = field(default_factory=dict)
    # Update only: the writes it applies, in order (Init adds the initial ones).
    fields: list[dict[str, int]] = field(default_factory=list)

    def dst_mac(self) -> str | None:
        return _dst_mac_from_fields(self.fields)


class FakeBess:
    """A pybess-shaped client with a model of the module graph.

    It enforces what bessd enforces: creating a module that exists is
    EEXIST, destroying or addressing one that does not is ENOENT, connecting
    an output gate that is wired is EBUSY, a gate beyond a class's gates is
    EINVAL, a command a class does not have is ENOTSUP, and a thread-unsafe
    command on a module that a running worker reaches is EBUSY. A restart
    replaces the model with the base pipeline and breaks the channel the
    way pybess does: the first connect() lets the channel go and fails, the
    next one succeeds, unless disconnect() was called in between.

    `errors` supplies the exception classes the controller catches: an
    object with Error(code, errmsg), RPCError and APIError, the way the
    pybess BESS class carries them.
    """

    # The commands each modelled class accepts, as in its cmds table. All
    # of them are THREAD_UNSAFE.
    COMMANDS: ClassVar[dict[str, tuple[str, ...]]] = {
        "IPLookup": ("add", "delete", "clear"),
        "Update": ("add", "clear"),
    }

    # Input and output gates per modelled class (module.h:238-239 defaults;
    # ip_lookup.h:54, merge.h:42, sink.h:42).
    GATES: ClassVar[dict[str, tuple[int, int]]] = {
        "IPLookup": (1, MAX_GATES),
        "Merge": (MAX_GATES, 1),
        "Sink": (1, 0),
    }

    # The fields a bess_error "match" may name, per op.
    MATCH_FIELDS: ClassVar[dict[str, tuple[str, ...]]] = {
        "pause": (),
        "resume": (),
        "reconnect": (),
        "list_modules": (),
        "get_module_info": ("name",),
        "create_module": ("name", "mclass"),
        "destroy_module": ("name",),
        "connect": ("m1", "m2", "ogate", "igate"),
        "disconnect": ("name", "ogate"),
        "module_command": ("name", "cmd", "prefix", "prefix_len", "gate"),
    }

    def __init__(self, recorder: Recorder, errors: Any, interfaces: list[str]) -> None:
        self._recorder = recorder
        self._errors = errors
        self._interfaces = list(interfaces)
        self.modules: dict[str, FakeModule] = {}
        self.base_modules: set[str] = set()
        self.paused = False
        self.broken = False
        self.connected = True
        self.daemon_up = True
        self.scripted: list[dict[str, Any]] = []
        self.reset_pipeline()

    # -- model

    def reset_pipeline(self) -> None:
        """The modules up4.bess creates for each interface, as far as routes go."""
        self.modules = {}
        for ifname in self._interfaces:
            routes = FakeModule("IPLookup")
            routes.routes[("0.0.0.0", 0)] = BAD_ROUTE_GATE
            routes.ogates[BAD_ROUTE_GATE] = (f"{ifname}bad_route", 0)
            self.modules[f"{ifname}Routes"] = routes
            self.modules[f"{ifname}bad_route"] = FakeModule("Sink")
            self.modules[f"{ifname}Merge"] = FakeModule("Merge")
            self.modules[f"{ifname}SrcEther"] = FakeModule("Update")
            self.modules[f"{ifname}Merge"].ogates[0] = (f"{ifname}SrcEther", 0)
        self.base_modules = set(self.modules)

    def seed(self, spec: dict[str, Any]) -> None:
        for name, module in spec.get("modules", {}).items():
            self.modules[name] = self._new_module(module["mclass"], module.get("arg"))
        for m1, ogate, m2, igate in spec.get("links", []):
            self.modules[m1].ogates[int(ogate)] = (m2, int(igate))
        for module, routes in spec.get("routes", {}).items():
            for prefix, gate in routes.items():
                addr, length, _ = _split_prefix(prefix)
                self.modules[module].routes[(addr, length)] = int(gate)

    def restart(self) -> None:
        """bessd restarts and is back at once: base pipeline, channel broken."""
        self.reset_pipeline()
        self.paused = False
        self.broken = True
        self.connected = False
        self.daemon_up = True

    def down(self) -> None:
        """bessd goes away and stays away: every reconnect attempt fails."""
        self.paused = False
        self.broken = True
        self.connected = False
        self.daemon_up = False

    def up(self) -> None:
        """bessd is back with the base pipeline."""
        self.reset_pipeline()
        self.daemon_up = True

    def reload(self) -> None:
        """The pipeline script is re-run on a live daemon: base modules back, channel intact."""
        self.reset_pipeline()
        self.paused = False

    def _has_worker(self, name: str) -> bool:
        """Whether a running worker reaches the module.

        bessd attaches workers to the modules downstream of its ports
        (ModuleGraph::PropagateActiveWorker); the base pipeline is, and so
        is anything wired from it. A module nothing points at has no worker,
        so a thread-unsafe command on it is fine even while traffic flows.
        """
        if self.paused:
            return False
        reached = {m for m in self.base_modules if m in self.modules}
        frontier = list(reached)
        while frontier:
            current = frontier.pop()
            for target, _ in self.modules[current].ogates.values():
                if target in self.modules and target not in reached:
                    reached.add(target)
                    frontier.append(target)
        return name in reached

    def state(self) -> dict[str, Any]:
        return {
            "modules": {
                name: {
                    "mclass": m.mclass,
                    "arg": {"dst_mac": m.dst_mac()} if m.mclass == "Update" else m.arg,
                }
                for name, m in self.modules.items()
            },
            "links": sorted(
                [m1, ogate, m2, igate]
                for m1, m in self.modules.items()
                for ogate, (m2, igate) in m.ogates.items()
            ),
            "routes": {
                name: {
                    f"{prefix}/{length}": gate
                    for (prefix, length), gate in m.routes.items()
                }
                for name, m in self.modules.items()
                if m.mclass == "IPLookup"
            },
            "forwarding": {
                name: {
                    f"{prefix}/{length}": self._forwarding(m, gate)
                    for (prefix, length), gate in m.routes.items()
                }
                for name, m in self.modules.items()
                if m.mclass == "IPLookup"
            },
        }

    def _forwarding(self, routes: FakeModule, gate: int) -> Any:
        """What happens to a packet that the route table sends to a gate.

        Follows the gate to the adjacency module and on to the merge, so the
        answer is independent of gate numbers and module names: a MAC and
        the module the frame reaches, "drop" for the sink or for IPLookup's
        own DROP_GATE, or "unwired" for a gate nothing is connected to.
        """
        if gate == DROP_GATE:
            return "drop"
        target = routes.ogates.get(gate)
        if target is None:
            return "unwired"
        module = self.modules.get(target[0])
        if module is None:
            return "unwired"
        if module.mclass == "Sink":
            return "drop"
        if module.mclass != "Update":
            return {"module": target[0]}
        onward = module.ogates.get(0)
        return {"dst_mac": module.dst_mac(), "to": onward[0] if onward else "unwired"}

    # -- failure injection

    def _fail(self, code: int, msg: str) -> None:
        self._recorder.record("error", errno.errorcode.get(code, str(code)))
        raise self._errors.Error(code, msg)

    def _check(self, op: str, **fields: Any) -> None:
        if self.broken:
            self._recorder.record("error", "RPCError")
            raise self._errors.RPCError("Broken RPC channel")
        if not self.connected:
            self._recorder.record("error", "APIError")
            raise self._errors.APIError("BESS daemon not connected")
        for scripted in list(self.scripted):
            if scripted["op"] != op:
                continue
            match = scripted.get("match", {})
            if all(fields.get(k) == v for k, v in match.items()):
                self.scripted.remove(scripted)
                code = scripted["code"]
                code = getattr(errno, code) if isinstance(code, str) else int(code)
                self._fail(code, f"scripted {op} failure")

    # -- the pybess API the controller uses

    def connect(self, grpc_url: str = "") -> None:
        """BESS.connect: bess/pybess/bess.py:223-247.

        The model assumes a lost daemon shows as READY -> TRANSIENT_FAILURE,
        which pybess records as its broken channel; a READY -> IDLE
        transition would instead be its closing channel, where the first
        connect() succeeds. Which one grpc reports has not been measured
        against a live daemon.
        """
        self._recorder.record("reconnect")
        if self.is_connected():
            raise self._errors.APIError("Already connected")
        if self.broken:
            self.disconnect()
            self._recorder.record("error", "RPCError")
            raise self._errors.RPCError(f"Connection to {grpc_url} failed")
        if not self.daemon_up:
            self._recorder.record("error", "RPCError")
            raise self._errors.RPCError(f"Connection to {grpc_url} failed")
        self.connected = True

    def disconnect(self) -> None:
        """BESS.disconnect: lets go of the channel, broken or not."""
        self.broken = False
        self.connected = False

    def is_connected(self) -> bool:
        return self.connected and not self.broken

    def is_connection_broken(self) -> bool:
        return self.broken

    def pause_all(self) -> None:
        self._recorder.record("pause")
        self._check("pause")
        self.paused = True

    def resume_all(self, check: bool = True) -> None:
        self._recorder.record("resume")
        self._check("resume")
        self.paused = False

    def create_module(
        self, mclass: str, name: str | None = None, arg: Any = None
    ) -> None:
        self._recorder.record(
            "create_module", name, mclass, _decode_module_arg(mclass, arg)
        )
        self._check("create_module", name=name, mclass=mclass)
        if name in self.modules:
            self._fail(errno.EEXIST, f"Module {name} exists")
        try:
            self.modules[name] = self._new_module(mclass, arg)
        except ValueError as err:
            self._fail(errno.EINVAL, str(err))

    @staticmethod
    def _new_module(mclass: str, arg: Any) -> FakeModule:
        module = FakeModule(mclass, arg)
        if mclass == "Update":
            module.fields = _update_fields(arg)  # Update::Init is CommandAdd
            if len(module.fields) > MAX_UPDATE_FIELDS:
                raise ValueError(f"max {MAX_UPDATE_FIELDS} variables can be specified")
        return module

    def destroy_module(self, name: str) -> None:
        self._recorder.record("destroy_module", name)
        self._check("destroy_module", name=name)
        if name not in self.modules:
            self._fail(errno.ENOENT, f"No module '{name}' found")
        del self.modules[name]
        for module in self.modules.values():
            for ogate, (m2, _) in list(module.ogates.items()):
                if m2 == name:
                    del module.ogates[ogate]

    def connect_modules(self, m1: str, m2: str, ogate: int = 0, igate: int = 0) -> None:
        self._recorder.record("connect", m1, int(ogate), m2, int(igate))
        self._check("connect", m1=m1, m2=m2, ogate=int(ogate), igate=int(igate))
        if m1 not in self.modules:
            self._fail(errno.ENOENT, f"No module '{m1}' found")
        if m2 not in self.modules:
            self._fail(errno.ENOENT, f"No module '{m2}' found")
        # module_graph.cc:330-338
        _, num_ogates = self.GATES.get(self.modules[m1].mclass, (1, 1))
        num_igates, _ = self.GATES.get(self.modules[m2].mclass, (1, 1))
        if int(ogate) >= num_ogates or int(igate) >= num_igates:
            self._fail(errno.EINVAL, f"Connection {m1}:{ogate}->{igate}:{m2} failed")
        if int(ogate) in self.modules[m1].ogates:
            self._fail(errno.EBUSY, f"Connection {m1}:{ogate}->{igate}:{m2} failed")
        self.modules[m1].ogates[int(ogate)] = (m2, int(igate))

    def disconnect_modules(self, name: str, ogate: int = 0) -> None:
        self._recorder.record("disconnect", name, int(ogate))
        self._check("disconnect", name=name, ogate=int(ogate))
        if name not in self.modules:
            self._fail(errno.ENOENT, f"No module '{name}' found")
        self.modules[name].ogates.pop(int(ogate), None)

    def list_modules(self) -> Any:
        """ListModules, shaped like the pybess response: .modules[i].name/.mclass."""
        self._recorder.record("list_modules")
        self._check("list_modules")
        return SimpleNamespace(
            error=SimpleNamespace(code=0, errmsg=""),
            modules=[
                SimpleNamespace(name=name, mclass=m.mclass, desc="")
                for name, m in self.modules.items()
            ],
        )

    def get_module_info(self, name: str) -> Any:
        """GetModuleInfo, shaped like the pybess response: .ogates[i].ogate/.name/.igate."""
        self._recorder.record("get_module_info", name)
        self._check("get_module_info", name=name)
        module = self.modules.get(name)
        if module is None:
            self._fail(errno.ENOENT, f"No module '{name}' found")
        igates: dict[int, list[Any]] = {}
        for m1, other in self.modules.items():
            for ogate, (m2, igate) in other.ogates.items():
                if m2 == name:
                    igates.setdefault(igate, []).append(
                        SimpleNamespace(ogate=ogate, name=m1)
                    )
        return SimpleNamespace(
            error=SimpleNamespace(code=0, errmsg=""),
            name=name,
            mclass=module.mclass,
            desc="",
            igates=[
                SimpleNamespace(
                    igate=igate, ogates=ogates, cnt=0, pkts=0, bytes=0, timestamp=0.0
                )
                for igate, ogates in sorted(igates.items())
            ],
            ogates=[
                SimpleNamespace(
                    ogate=ogate,
                    cnt=0,
                    pkts=0,
                    bytes=0,
                    timestamp=0.0,
                    name=m2,
                    igate=igate,
                )
                for ogate, (m2, igate) in sorted(module.ogates.items())
            ],
            metadata=[],
            deadends=0,
        )

    def run_module_command(self, name: str, cmd: str, arg_type: str, arg: Any) -> None:
        self._recorder.record(
            "module_command", name, cmd, dict(arg) if isinstance(arg, dict) else arg
        )
        fields = {"name": name, "cmd": cmd}
        if isinstance(arg, dict):
            fields.update(
                {k: v for k, v in arg.items() if k in ("prefix", "prefix_len", "gate")}
            )
        self._check("module_command", **fields)
        module = self.modules.get(name)
        if module is None:
            self._fail(errno.ENOENT, f"No module '{name}' found")
        if cmd not in self.COMMANDS.get(module.mclass, ()):
            self._fail(
                errno.ENOTSUP, f"'{module.mclass}' does not support command '{cmd}'"
            )
        # Every modelled command is THREAD_UNSAFE in its module's table, so
        # bessd refuses it while a worker attached to the module runs
        # (module.cc:99).
        if self._has_worker(name):
            self._fail(
                errno.EBUSY,
                f"There is a running worker and command '{cmd}' is not MT safe",
            )
        if module.mclass == "Update":
            if cmd == "clear":
                module.fields = []
            else:
                try:
                    added = _update_fields(arg)
                except ValueError as err:
                    self._fail(errno.EINVAL, str(err))
                if len(module.fields) + len(added) > MAX_UPDATE_FIELDS:
                    self._fail(
                        errno.EINVAL,
                        f"max {MAX_UPDATE_FIELDS} variables can be specified",
                    )
                module.fields.extend(added)
        if module.mclass == "IPLookup":
            if cmd == "add":
                gate = int(arg["gate"])
                if gate >= MAX_GATES and gate != DROP_GATE:  # is_valid_gate
                    self._fail(errno.EINVAL, "Invalid gate")
                module.routes[(arg["prefix"], int(arg["prefix_len"]))] = gate
            elif cmd == "delete":
                key = (arg["prefix"], int(arg["prefix_len"]))
                if key[1] == 0:
                    # ip_lookup.cc:268-269: the default becomes DROP_GATE, not
                    # the sink gate the pipeline had wired.
                    module.routes[key] = DROP_GATE
                elif key not in module.routes:
                    self._fail(errno.ENOENT, "rpm_lpm_delete() failed")
                else:
                    del module.routes[key]
            elif cmd == "clear":
                module.routes = {k: v for k, v in module.routes.items() if k[1] == 0}


# ---------------------------------------------------------------------------
# Adapters


class Adapter:
    """What an implementation must provide to be driven by a trace."""

    def __init__(
        self,
        kernel: FakeKernel,
        bess: FakeBess,
        clock: VirtualClock,
        recorder: Recorder,
        interfaces: list[str],
    ) -> None:
        raise NotImplementedError

    def start(self) -> None:
        raise NotImplementedError

    def deliver(self, message: dict[str, Any]) -> None:
        raise NotImplementedError

    def sighup(self) -> None:
        raise NotImplementedError

    def tick(self, seconds: float) -> None:
        """Time passes. An implementation with timers runs them here."""

    def stop(self) -> None:
        """Undo any patching."""


# ---------------------------------------------------------------------------
# Matching


@dataclass
class Mismatch:
    step: int | str
    kind: str
    expected: Any
    actual: Any

    def __str__(self) -> str:
        return (
            f"step {self.step} ({self.kind}):\n"
            f"  expected: {json.dumps(self.expected, sort_keys=True, default=str)}\n"
            f"  actual:   {json.dumps(self.actual, sort_keys=True, default=str)}"
        )


def matches(pattern: Any, value: Any) -> bool:
    """Structural match; the string "*" in a pattern matches any value."""
    if pattern == "*":
        return True
    if isinstance(pattern, list):
        return (
            isinstance(value, list)
            and len(pattern) == len(value)
            and all(matches(p, v) for p, v in zip(pattern, value))
        )
    if isinstance(pattern, dict):
        return (
            isinstance(value, dict)
            and set(pattern) == set(value)
            and all(matches(p, value[k]) for k, p in pattern.items())
        )
    return pattern == value


def effective(ops: list[list[Any]]) -> list[list[Any]]:
    """The ops a non-strict block counts: no pacing, reads or errors, and
    not an op the daemon refused (one followed by an error entry)."""
    kept = []
    for i, op in enumerate(ops):
        if op[0] in NON_EFFECTIVE:
            continue
        if i + 1 < len(ops) and ops[i + 1][0] == "error":
            continue
        kept.append(op)
    return kept


def _assign(patterns: list[Any], values: list[Any]) -> tuple[list[int], list[int]]:
    """Pairs as many patterns as possible with distinct matching values.

    Returns the indexes of the unmatched patterns and of the unmatched
    values. A pattern with a "*" can match several values, so this is a
    maximum bipartite matching found with augmenting paths. Free values are
    tried before owned ones, so a run of identical ops matches without
    recursion.
    """
    candidates = [
        [j for j, v in enumerate(values) if matches(pat, v)] for pat in patterns
    ]
    owner: dict[int, int] = {}  # value index -> pattern index

    def augment(i: int, seen: set[int]) -> bool:
        for j in candidates[i]:
            if j not in owner:
                owner[j] = i
                return True
        for j in candidates[i]:
            if j in seen:
                continue
            seen.add(j)
            if augment(owner[j], seen):
                owner[j] = i
                return True
        return False

    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, len(patterns) * 2 + 1000))
    try:
        for i in range(len(patterns)):
            augment(i, set())
    finally:
        sys.setrecursionlimit(limit)
    matched = set(owner.values())
    return (
        [i for i in range(len(patterns)) if i not in matched],
        [j for j in range(len(values)) if j not in owner],
    )


def compare_ops(
    expected: list[Any],
    actual: list[list[Any]],
    ordered: bool,
    strict: bool,
    allow: list[Any] | None = None,
) -> tuple[Any, Any] | None:
    """Returns (expected, actual) in the compared form on a mismatch, else None.

    strict keeps the pacing, error and read entries; otherwise only the
    effective ops are compared. ordered compares the sequence; otherwise
    the ops are matched regardless of order. Each op in allow may appear
    once in actual without being expected, in either mode; the expected
    ops are matched first, so an allowed pattern cannot take the one op an
    expected pattern needs.
    """
    exp = [op for op in expected if isinstance(op, list)]
    act = actual if strict else effective(actual)
    exp = exp if strict else effective(exp)
    allowed = [op for op in allow if isinstance(op, list)] if allow else []
    if ordered:
        return _compare_sequence(exp, act, allowed)
    # One matching over expected and allowed patterns together, expected
    # first: augmenting paths may move an expected pattern to another value
    # so that an allowed one fits, but never unmatch it.
    unmatched, extra = _assign(exp + allowed, act)
    missing = [exp[i] for i in unmatched if i < len(exp)]
    if missing or extra:
        return {"missing": missing}, {"extra": [act[j] for j in extra]}
    return None


def paused_sleep(ops: list[list[Any]]) -> float:
    """Seconds slept between a pause the daemon accepted and the next resume:
    time the workers spent stopped while the controller waited."""
    paused = False
    total = 0.0
    for i, op in enumerate(ops):
        refused = i + 1 < len(ops) and ops[i + 1][0] == "error"
        if op[0] == "pause" and not refused:
            paused = True
        elif op[0] == "resume" and not refused:
            paused = False
        elif op[0] == "sleep" and paused:
            total += float(op[1])
    return total


def compare_checkpoint(
    step: dict[str, Any], ops: list[list[Any]]
) -> tuple[Any, Any] | None:
    """An "expect" step against the recorded ops: the op comparison the
    step asks for, then its bound on sleep under pause."""
    result = compare_ops(
        step["expect"],
        ops,
        bool(step.get("ordered")),
        bool(step.get("strict")),
        step.get("allow"),
    )
    if result:
        return result
    bound = step.get("max_paused_sleep")
    if bound is not None and paused_sleep(ops) > float(bound):
        return {"max_paused_sleep": bound}, {"paused_sleep": paused_sleep(ops)}
    return None


def _compare_sequence(
    exp: list[Any], act: list[Any], allowed: list[Any]
) -> tuple[Any, Any] | None:
    """Ordered comparison; each allowed pattern may absorb one actual op at
    whichever position makes the sequence match. Iterative, so a long
    block cannot exhaust the stack."""
    n_allowed = len(allowed)
    full = (1 << n_allowed) - 1
    # ok[i][j][mask]: exp[i:] matches act[j:] with the allowed patterns in
    # mask still available.
    ok = [
        [[False] * (full + 1) for _ in range(len(act) + 1)] for _ in range(len(exp) + 1)
    ]
    for mask in range(full + 1):
        ok[len(exp)][len(act)][mask] = True
    for j in range(len(act) - 1, -1, -1):
        for i in range(len(exp), -1, -1):
            for mask in range(full + 1):
                result = False
                if i < len(exp) and matches(exp[i], act[j]) and ok[i + 1][j + 1][mask]:
                    result = True
                else:
                    for k in range(n_allowed):
                        if (
                            mask & (1 << k)
                            and matches(allowed[k], act[j])
                            and ok[i][j + 1][mask & ~(1 << k)]
                        ):
                            result = True
                            break
                ok[i][j][mask] = result
    if ok[0][0][full]:
        return None
    # Report where the sequences first part company.
    i = j = 0
    while i < len(exp) and j < len(act) and matches(exp[i], act[j]):
        i += 1
        j += 1
    return {"first_divergence": i, "expected": exp}, {
        "first_divergence": j,
        "actual": act,
    }


def compare_state(
    expected: dict[str, Any], state: dict[str, Any]
) -> list[tuple[str, Any, Any]]:
    problems: list[tuple[str, Any, Any]] = []
    for name, want in expected.get("modules", {}).items():
        have = state["modules"].get(name)
        if have is None:
            problems.append((f"module {name}", want, None))
            continue
        for key, value in (want or {}).items():
            if not matches(value, have.get(key)):
                problems.append((f"module {name}.{key}", value, have.get(key)))
    for name in expected.get("absent", []):
        if name in state["modules"]:
            problems.append((f"module {name}", "absent", state["modules"][name]))
    for module, want in expected.get("routes", {}).items():
        have = state["routes"].get(module)
        if not matches(dict(want), have):
            problems.append((f"routes {module}", want, have))
    for link in expected.get("links", []):
        if not any(matches(list(link), have) for have in state["links"]):
            problems.append(("link", link, "absent"))
    for module, want in expected.get("forwarding", {}).items():
        have = state["forwarding"].get(module)
        if not matches(want, have):
            problems.append((f"forwarding {module}", want, have))
    return problems


def state_key_satisfied(
    spec: dict[str, Any], key: str, recorded: dict[str, Any]
) -> bool:
    """Whether the intended spec for one state key holds on a recorded
    state block (as fill writes it: "modules" and "absent" together from
    the module table, the other keys in state form)."""
    pseudo: dict[str, Any] = {
        "modules": {},
        "routes": {},
        "links": [],
        "forwarding": {},
    }
    if key in ("modules", "absent"):
        pseudo["modules"] = recorded.get("modules", {})
        want = {k: spec[k] for k in ("modules", "absent") if k in spec}
    else:
        pseudo[key] = recorded.get(key) or pseudo[key]
        want = {key: spec[key]} if key in spec else {}
    if not want:
        return True
    return not compare_state(want, pseudo)


# ---------------------------------------------------------------------------
# Traces


def load_trace(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _lint_ops(where: str, ops: Any) -> list[str]:
    problems = []
    if not isinstance(ops, list):
        return [f"{where}: not a list"]
    for op in ops:
        if not isinstance(op, list):
            problems.append(f"{where}: {op!r} is not an op")
            continue
        if not op or op[0] not in OP_ARITY:
            problems.append(f"{where}: unknown op {op!r}")
        elif len(op) != OP_ARITY[op[0]]:
            problems.append(
                f"{where}: {op[0]} takes {OP_ARITY[op[0]] - 1} argument(s), got {op!r}"
            )
    return problems


def _needs_because(step: dict[str, Any], index: int, block: str) -> list[str]:
    because = step.get("because")
    if (
        not isinstance(because, str)
        or not because.strip()
        or because.startswith(FILL_IN)
    ):
        return [f'step {index}: {block} needs a "because"']
    return []


def validate_trace(trace: dict[str, Any]) -> list[str]:
    """Problems with a trace's shape; empty when it is well-formed."""
    problems: list[str] = []
    if not trace.get("interfaces"):
        problems.append("no interfaces")
    for key in trace.get("kernel", {}):
        if key not in ("links", "routes", "neighbors"):
            problems.append(f"kernel: unknown key {key!r}")
    steps = trace.get("steps")
    if not isinstance(steps, list) or not steps:
        return problems + ["no steps"]
    for index, step in enumerate(steps):
        keys = set(step) - {"note"}
        inputs = keys & INPUT_STEPS
        if inputs:
            if len(inputs) > 1 or keys - inputs:
                problems.append(
                    f"step {index}: an input step carries one key, got {sorted(keys)}"
                )
            if "bess_error" in inputs:
                problems += _validate_bess_error(step["bess_error"], index)
            continue
        if "expect" in keys or "expect_python" in keys:
            if keys - OPS_CHECKPOINT_KEYS:
                problems.append(
                    f"step {index}: unknown key(s) {sorted(keys - OPS_CHECKPOINT_KEYS)}"
                )
            if "expect" not in keys:
                problems.append(f"step {index}: expect_python without expect")
            else:
                problems += _lint_ops(f"step {index} expect", step["expect"])
            if "allow" in keys:
                problems += _lint_ops(f"step {index} allow", step["allow"])
            if "expect_python" in keys:
                problems += _lint_ops(
                    f"step {index} expect_python", step["expect_python"]
                )
                problems += _needs_because(step, index, "expect_python")
            elif "because" in keys:
                problems.append(f"step {index}: because without expect_python")
        elif "expect_state" in keys or "expect_state_python" in keys:
            if keys - STATE_CHECKPOINT_KEYS:
                problems.append(
                    f"step {index}: unknown key(s) {sorted(keys - STATE_CHECKPOINT_KEYS)}"
                )
            if "expect_state" not in keys:
                problems.append(
                    f"step {index}: expect_state_python without expect_state"
                )
            for name in ("expect_state", "expect_state_python"):
                for key in step.get(name, {}):
                    if key not in STATE_KEYS:
                        problems.append(f"step {index}: {name} has unknown key {key!r}")
            if "expect_state_python" in keys:
                problems += _needs_because(step, index, "expect_state_python")
            elif "because" in keys:
                problems.append(f"step {index}: because without expect_state_python")
        else:
            problems.append(f"step {index}: unknown step {sorted(keys)}")
    if not {"expect", "expect_state"} & set(steps[-1]):
        problems.append("the last step is not a checkpoint")
    return problems


def _validate_bess_error(spec: Any, index: int) -> list[str]:
    if not isinstance(spec, dict) or spec.get("op") not in FakeBess.MATCH_FIELDS:
        return [
            f"step {index}: bess_error op must be one of {sorted(FakeBess.MATCH_FIELDS)}"
        ]
    problems = []
    op = spec["op"]
    for name in spec.get("match", {}):
        if name not in FakeBess.MATCH_FIELDS[op]:
            problems.append(
                f"step {index}: bess_error match field {name!r} is not one of "
                f"{FakeBess.MATCH_FIELDS[op]} for {op}"
            )
    code = spec.get("code")
    if not (isinstance(code, int) or (isinstance(code, str) and hasattr(errno, code))):
        problems.append(f"step {index}: bess_error code {code!r} is not an errno name")
    return problems


def run_trace(
    trace: dict[str, Any],
    make_adapter: Any,
    errors: Any,
    use_python_expectations: bool = False,
    record: bool = False,
) -> tuple[list[Mismatch], list[dict[str, Any]]]:
    """Runs one trace.

    With use_python_expectations, a checkpoint that carries an
    "expect_python" or "expect_state_python" block is checked against it
    (the ops block strictly and in order; the state block's keys laid over
    the intended state); otherwise the intended "expect" and "expect_state"
    are checked and the Python blocks are ignored.

    With record, every checkpoint's actual ops or state is returned as a
    list of {"step": index, "ops": [...]} / {"step": index, "state": {...}}
    instead of being compared.
    """
    problems = validate_trace(trace)
    if problems:
        raise ValueError("invalid trace:\n  " + "\n  ".join(problems))
    interfaces = list(trace["interfaces"])
    recorder = Recorder()
    clock = VirtualClock(recorder)
    kernel = FakeKernel(trace.get("kernel", {}))
    bess = FakeBess(recorder, errors, interfaces)
    mismatches: list[Mismatch] = []
    recorded: list[dict[str, Any]] = []
    adapter = make_adapter(kernel, bess, clock, recorder, interfaces)
    try:
        for index, step in enumerate(trace["steps"]):
            if "start" in step:
                adapter.start()
            elif "route_add" in step:
                adapter.deliver(kernel.route_add(step["route_add"]))
            elif "route_del" in step:
                adapter.deliver(kernel.route_del(step["route_del"]))
            elif "neigh_add" in step:
                adapter.deliver(kernel.neigh_add(step["neigh_add"]))
            elif "neigh_change" in step:
                adapter.deliver(kernel.neigh_add(step["neigh_change"]))
            elif "neigh_unresolved" in step:
                neigh = dict(step["neigh_unresolved"])
                neigh.pop("lladdr", None)
                adapter.deliver(kernel.neigh_add(neigh))
            elif "neigh_del" in step:
                adapter.deliver(kernel.neigh_del(step["neigh_del"]))
            elif "bess_restart" in step:
                bess.restart()
            elif "bess_down" in step:
                bess.down()
            elif "bess_up" in step:
                bess.up()
            elif "bess_reload" in step:
                bess.reload()
            elif "bess_seed" in step:
                bess.seed(step["bess_seed"])
            elif "bess_error" in step:
                bess.scripted.append(dict(step["bess_error"]))
            elif "sighup" in step:
                adapter.sighup()
            elif "tick" in step:
                adapter.tick(float(step["tick"]))
            elif "expect" in step:
                ops = recorder.take()
                if record:
                    recorded.append({"step": index, "ops": ops})
                    continue
                if use_python_expectations and "expect_python" in step:
                    result = compare_ops(step["expect_python"], ops, True, True)
                    if result:
                        mismatches.append(Mismatch(index, "expect_python", *result))
                else:
                    result = compare_checkpoint(step, ops)
                    kind = "expect (python)" if use_python_expectations else "expect"
                    if result:
                        mismatches.append(Mismatch(index, kind, *result))
            else:  # expect_state
                if record:
                    recorded.append({"step": index, "state": bess.state()})
                    continue
                want = dict(step.get("expect_state", {}))
                kind = "expect_state"
                if use_python_expectations and "expect_state_python" in step:
                    # The recorded block overrides only the keys where the
                    # Python differs; the rest of the intended state holds.
                    want.update(step["expect_state_python"])
                    kind = "expect_state_python"
                for what, got_want, have in compare_state(want, bess.state()):
                    mismatches.append(Mismatch(index, f"{kind} {what}", got_want, have))
        if not record:
            if recorder.ops:
                mismatches.append(
                    Mismatch("end", "ops after the last expect", [], recorder.ops)
                )
            if bess.scripted:
                mismatches.append(
                    Mismatch("end", "bess_error never triggered", bess.scripted, [])
                )
    finally:
        adapter.stop()
    return mismatches, recorded


def fill_python_expectations(
    trace: dict[str, Any], recorded: list[dict[str, Any]]
) -> int:
    """Writes what the Python did into the checkpoints where it differs from "expect".

    Adds "expect_python" (strict, ordered) to an "expect" step whose ops do
    not match, and "expect_state_python" to an "expect_state" step that does
    not match, holding only the state keys on which the Python differs.
    Each new block gets a "because" to fill in; the trace is invalid until
    it is. Checkpoints already carrying a Python block are left alone.
    Returns the number of blocks written.
    """
    by_step = {r["step"]: r for r in recorded}
    written = 0
    for index, step in enumerate(trace["steps"]):
        record = by_step.get(index)
        if record is None:
            continue
        if (
            "expect" in step
            and "expect_python" not in step
            and compare_checkpoint(step, record["ops"])
        ):
            step["expect_python"] = record["ops"]
            step["because"] = f"{FILL_IN}: why the Python differs here"
            written += 1
        if "expect_state" in step and "expect_state_python" not in step:
            state = record["state"]
            want = step["expect_state"]
            have: dict[str, Any] = {}
            problems = {what.split(" ")[0] for what, _, _ in compare_state(want, state)}
            if "module" in problems:
                names = list(want.get("modules", {})) + list(want.get("absent", []))
                have["modules"] = {
                    n: state["modules"][n] for n in names if n in state["modules"]
                }
                have["absent"] = [n for n in names if n not in state["modules"]]
            if "routes" in problems:
                have["routes"] = {m: state["routes"].get(m) for m in want["routes"]}
            if "link" in problems:
                have["links"] = [
                    link
                    for link in state["links"]
                    if any(matches(list(w), link) for w in want["links"])
                ]
            if "forwarding" in problems:
                have["forwarding"] = {
                    m: state["forwarding"].get(m) for m in want["forwarding"]
                }
            if have:
                step["expect_state_python"] = have
                step["because"] = f"{FILL_IN}: why the Python differs here"
                written += 1
    if written and not trace.get("python_differs"):
        trace["python_differs"] = True
    return written


def main(argv: list[str]) -> int:
    """record: prints what the Python did at each checkpoint.
    fill: writes it into the trace where it differs from the intended ops.
    check: validates the trace files' shape."""
    if len(argv) < 2 or argv[0] not in ("record", "fill", "check"):
        print(
            "usage: python -m conf.traces.runner (record|fill|check) <trace.json>...",
            file=sys.stderr,
        )
        return 2
    if argv[0] == "check":
        bad = 0
        for name in argv[1:]:
            problems = validate_trace(load_trace(Path(name)))
            for problem in problems:
                print(f"{name}: {problem}")
            bad += bool(problems)
        return 1 if bad else 0

    from conf.traces.python_adapter import PythonAdapter, errors

    if argv[0] == "fill":
        for name in argv[1:]:
            trace = load_trace(Path(name))
            _, recorded = run_trace(trace, PythonAdapter, errors, record=True)
            written = fill_python_expectations(trace, recorded)
            if written:
                with open(name, "w", encoding="utf-8") as handle:
                    json.dump(trace, handle, indent=2)
                    handle.write("\n")
            print(f"{name}: {written} python block(s) written")
        return 0

    for name in argv[1:]:
        trace = load_trace(Path(name))
        _, recorded = run_trace(trace, PythonAdapter, errors, record=True)
        print(f"== {name}")
        for checkpoint in recorded:
            print(f"-- step {checkpoint['step']}")
            if "ops" in checkpoint:
                for op in checkpoint["ops"]:
                    print("  " + json.dumps(op))
            else:
                print("  " + json.dumps(checkpoint["state"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
