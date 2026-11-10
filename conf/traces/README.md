<!--
SPDX-FileCopyrightText: 2026 Intel Corporation
SPDX-License-Identifier: Apache-2.0
-->

# Route control traces

Replay scenarios for the route controller: the process that copies the
kernel's routes and neighbors into the BESS pipeline (`route_control.py`
today). Each scenario is a JSON file whose inputs are kernel facts and whose
expected outputs are BESS control calls. Nothing in a file names a method of
any implementation, so the same scenarios can be run against a port.

```
python3 -m unittest conf.test_route_control_traces -v      # from the repository root
python3 -m conf.traces.runner check  conf/traces/scenarios/*.json
python3 -m conf.traces.runner record conf/traces/scenarios/<name>.json
python3 -m conf.traces.runner fill   conf/traces/scenarios/<name>.json
```

The suite needs only the standard library. `route_control.py` imports
`pyroute2`, `scapy` and `pybess` at module level; when they are not
installed the adapter installs stub modules with the names it imports, since
the harness replaces every code path that uses them.

## How a scenario runs

```
scenario.json ──> runner ──┬──> fake kernel ──(dumps, lookups, events)──> controller under test
                           │                                                     │
                           └──> fake BESS client <─────────(RPCs)────────────────┘
                                      │
                                 recorded ops  ──(compare)──  expected ops
```

- The fake kernel holds the route, neighbor and link tables and produces
  `netlink` messages in the shape `pyroute2` gives them. Every scenario's
  kernel is a UPF host's: the connected route and the local and broadcast
  entries of each interface, then whatever the scenario adds. A change the
  kernel could not make, such as deleting a route it does not hold, is a
  scenario error.
- The fake BESS client records every call and keeps a model of the module
  graph: modules, gate wiring, each `IPLookup` table and each `Update`
  module's writes. It enforces what `bessd` enforces (`EEXIST`, `ENOENT`,
  `EBUSY` on a wired gate, `EBUSY` on a thread-unsafe command while a worker
  reaches the module, `EINVAL` on gate ranges and field limits, `ENOTSUP`,
  the `DROP_GATE` sentinel) and breaks its channel the way `pybess` does
  after a daemon restart. Reads (`ListModules`, `GetModuleInfo`) answer with
  `pybess`-shaped objects.
- Sleeps go to a virtual clock and are recorded. A probe of an unresolved
  next hop is recorded, and whether the neighbor then appears is a step in
  the scenario, since the kernel's answer is environment, not controller
  logic.
- The Python adapter never starts the controller's threads. Messages go to
  its two handlers directly, in scenario order; the ping loop's own body
  runs at start and whenever its period has elapsed on the virtual clock.

## Checkpoints

`expect` is the intended behavior at a checkpoint: the ops since the last
`expect`. By default the effective ops are compared ignoring order; effective
means not pacing (`pause`, `resume`, `sleep`), not a read, not an error entry,
and not an op the daemon refused (one followed by an error entry), so a
refused call never satisfies an intent. `"ordered": true` compares the
sequence; `"strict": true` keeps every entry; `"allow"` lists ops that may
each appear once without being expected, in either mode (a harmless re-add,
say), and expected ops are matched first so an allowed pattern cannot take
the one op an expected pattern needs; `"max_paused_sleep"` bounds the seconds
slept while the workers were paused, which is how a retry loop that holds the
datapath is caught without a strict block. `"*"` in an expected value matches
anything, for gate numbers an implementation is free to pick.

`expect_state` checks the fake's model after a step. Its `forwarding` view
follows each prefix from the route table through the gate to the adjacency
module and on to the merge, so it states the outcome a packet sees (this
destination MAC, reaching this module; or drop; or a gate with nothing behind it) without
naming gates or modules.

`expect_python` is what `route_control.py` on `main` does today at a
checkpoint, strict and ordered, and `expect_state_python` holds the state
keys on which it differs. Both are written by `fill`, appear only where the
Python differs from the intent, and carry a `because` naming the bug; a
trace without one is rejected. The scenario is then marked
`"python_differs": true`.

A trace must end with a checkpoint, and ops after the last `expect` fail the
run, as does a `bess_error` that was never triggered. `check` validates the
files' shape: step keys, op names and argument counts, `bess_error` fields.

## Tests

Each scenario gives one test, `test_<name>`, which checks what the Python
is documented to do: the recorded block where there is one, the intended
block elsewhere. Every scenario passes against `main`, and there are no
expected failures. When a bug is fixed, the recorded block stops matching
and the test fails until the block is removed; a second test,
`test_<name>_recorded_divergence_is_real`, fails if a recorded block is
left in place once it satisfies the intent. A port runs the intended blocks
only. `HarnessTests` cover the harness's own rules.

## Scenarios

| # | Scenario | Python on main |
|---|----------|----------------|
| 01 | Bootstrap, both gateways resolved | as intended |
| 02 | Bootstrap, one gateway unresolved, resolves later | as intended |
| 03 | Duplicate route event is a no-op | as intended |
| 04 | Two prefixes through one next hop share an adjacency | as intended |
| 05 | Deleting the last route through an `onlink` gateway destroys its adjacency | differs: destroyed under a name it was never created with, five times, and leaks |
| 06 | Route replaced with another `onlink` gateway | differs: the same leak of the old adjacency |
| 07 | Attached network, hosts known at start | as intended |
| 08 | Attached network, host appears later | as intended |
| 09 | Routes and neighbors on a foreign interface | as intended |
| 10 | Gateway MAC changes | differs: frames keep the old MAC |
| 11 | Gateway neighbor entry deleted | differs: forwarding keeps the last MAC, as it should, but nothing probes, so a MAC that changes meanwhile is never learned |
| 12 | Controller restarts, `bessd` state intact | differs: `EBUSY` on the existing link is retried five times, 2 s each, with the workers paused |
| 13 | Pipeline reload and `SIGHUP` | as intended |
| 14 | `bessd` restart | differs: the channel is broken for good; nothing is programmed again |
| 15 | Next hop never resolves | as intended |
| 16 | Route deleted while its next hop is unresolved | as intended |
| 17 | The same gateway address on both interfaces | differs: the second interface gets a gate with nothing behind it; its traffic is dropped |
| 18 | A default route in another table | differs: taken as a move of the main table's default, then deleted with it |
| 19 | `bessd` refuses to create the adjacency | differs: the prefixes point at a gate with nothing behind it for good |
| 20 | `bessd` refuses a route add | differs: the route is forgotten until the next route event; 10 s paused |
| 21 | Attached network withdrawn | differs: the adjacency leaks as in 05, per host |
| 23 | Neighbor event without a link-layer address | as intended |
| 24 | IPv6 routes and neighbors | as intended (ignored) |
| 25 | The kernel's own local and broadcast entries | as intended (ignored) |
| 28 | Route replaced with an unresolved gateway | as intended |
| 29 | Route withdrawn between a pipeline reset and `SIGHUP` | differs: a delete the daemon refuses as absent is retried with the workers paused |
| 30 | `SIGHUP` with no pipeline reset behind it | differs: as 12 |

Not covered: the host cap on an attached network (512 hosts), gate
exhaustion (8191 next hops), multi-path routes (no `RTA_OIF`, ignored by the
controller, which the fake kernel cannot emit), a failing probe (`send_ping`
is replaced), and a `resume_all` constraint failure.

## Adding an implementation

Implement `Adapter` from `runner.py`: construct the controller against the
fake kernel and fake BESS client, then `start`, `deliver(message)`,
`sighup`, `tick(seconds)` and `stop`. The fake BESS client has the `pybess`
method names (`pause_all`, `create_module`, `connect_modules`,
`list_modules`, `get_module_info`, ...); a Go implementation would be
driven over a small shim that turns its gRPC calls into the same recorded
ops.

## Limits

The Python adapter drives internal handler methods, so it is coupled to the
Python's method names; the scenario files are not. Replay bypasses the two
threads, so a race between the ping thread and the event thread in a real
run does not show in a trace. Deleting an attached network iterates a set in
the Python, so the order of its host-route deletes is not deterministic; the
scenarios keep to one host there. The messages are synthetic `pyroute2`
dictionaries of the same shape the unit tests build. The broken-channel model
assumes a lost daemon shows as a transient failure to `grpc`; an idle
transition would let the first reconnect succeed, and which one a live
daemon produces has not been measured.
