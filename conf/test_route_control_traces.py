# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation

"""Runs the route-control traces in conf/traces/scenarios against route_control.py.

Each scenario gives one test, and a second where the Python differs from
the intended behavior today:

- test_<name> checks what route_control.py is documented to do at every
  checkpoint: the recorded "expect_python" block where the scenario has
  one, the intended "expect" block elsewhere. Every scenario passes against
  main. When a bug is fixed, the recorded block no longer matches and the
  test fails until that block is removed, at which point the intended
  block takes over.
- test_<name>_recorded_divergence_is_real checks that each recorded block
  still differs from the intended one, so a recorded block cannot linger
  once the Python matches the intent.

There are no expected failures: a green run means the Python does what the
scenarios say it does, and the scenarios say where that is not yet what it
should do. Every trace is validated for shape before it runs, and the
HarnessTests cover the harness's own rules.

Run from the repository root:

    python3 -m unittest conf.test_route_control_traces -v

Record what the Python does at each checkpoint of a scenario with:

    python3 -m conf.traces.runner record conf/traces/scenarios/<name>.json
"""

import logging
import time
import unittest
from pathlib import Path

from conf.traces import runner
from conf.traces.python_adapter import PythonAdapter, errors

SCENARIOS = sorted((Path(__file__).parent / "traces" / "scenarios").glob("*.json"))


class TraceTests(unittest.TestCase):
    """One test per scenario; see the module docstring."""

    maxDiff = None


def _tests_for(path: Path):
    def documented(self):
        trace = runner.load_trace(path)
        mismatches, _ = runner.run_trace(
            trace, PythonAdapter, errors, use_python_expectations=True
        )
        self.assertEqual([], mismatches, "\n" + "\n".join(str(m) for m in mismatches))

    def recorded_divergence_is_real(self):
        trace = runner.load_trace(path)
        for index, step in enumerate(trace["steps"]):
            if "expect_python" in step:
                self.assertIsNotNone(
                    runner.compare_checkpoint(step, step["expect_python"]),
                    f"step {index}: expect_python satisfies expect; remove it",
                )
            if "expect_state_python" in step:
                self.assertFalse(
                    all(
                        runner.state_key_satisfied(
                            step["expect_state"], key, step["expect_state_python"]
                        )
                        for key in step["expect_state_python"]
                    ),
                    f"step {index}: expect_state_python satisfies expect_state; remove it",
                )

    return documented, recorded_divergence_is_real


_seen: set[str] = set()
for _path in SCENARIOS:
    _trace = runner.load_trace(_path)
    _name = _path.stem.replace("-", "_")
    if _name in _seen:
        raise RuntimeError(f"two scenarios would share the test name {_name}")
    _seen.add(_name)
    _documented, _divergence = _tests_for(_path)
    _documented.__doc__ = _trace.get("description", _name)
    setattr(TraceTests, f"test_{_name}", _documented)
    if any("expect_python" in s or "expect_state_python" in s for s in _trace["steps"]):
        _divergence.__doc__ = (
            f"{_name}: the recorded Python behavior still differs from the intended one"
        )
        setattr(TraceTests, f"test_{_name}_recorded_divergence_is_real", _divergence)


class HarnessTests(unittest.TestCase):
    """The harness's own behavior: validation, matching, and the fake daemon's rules."""

    maxDiff = None

    def _bess(self):
        recorder = runner.Recorder()
        return runner.FakeBess(recorder, errors, ["core"]), recorder

    def _trace(self, steps, kernel=None):
        return {
            "interfaces": ["core"],
            "kernel": kernel or {"links": {"3": "core"}},
            "steps": steps,
        }

    # -- validation

    def test_unknown_step_keys_are_rejected(self):
        for steps in (
            [{"start": True}, {"expect": [], "alow": []}],
            [{"start": True}, {"expect": [], "expect_state": {}}],
            [{"start": True}, {"expect_python": []}],
            [
                {"start": True},
                {"expect": [], "expect_python": [], "because": "FILL IN: later"},
            ],
            [{"start": True, "tick": 1}, {"expect": []}],
            [{"start": True}, {"expect": [["destroy_module"]]}],
            [{"start": True}, {"expect": [["frobnicate", "x"]]}],
            [{"start": True}, {"expect_state": {"module": {}}}],
            [{"start": True}],
        ):
            self.assertTrue(runner.validate_trace(self._trace(steps)), steps)
        self.assertEqual(
            [],
            runner.validate_trace(
                self._trace(
                    [{"start": True}, {"expect": [], "allow": [["probe", "*"]]}]
                )
            ),
        )

    def test_bess_error_fields_are_validated(self):
        bad = [
            {
                "bess_error": {
                    "op": "module_command",
                    "code": "EIO",
                    "match": {"arg": 1},
                }
            },
            {"expect": []},
        ]
        self.assertTrue(runner.validate_trace(self._trace(bad)))
        bad = [{"bess_error": {"op": "destroy", "code": "EIO"}}, {"expect": []}]
        self.assertTrue(runner.validate_trace(self._trace(bad)))
        bad = [{"bess_error": {"op": "connect", "code": "ENOSUCH"}}, {"expect": []}]
        self.assertTrue(runner.validate_trace(self._trace(bad)))

    def test_untriggered_bess_error_and_leftover_ops_are_reported(self):
        trace = self._trace(
            [
                {
                    "bess_error": {
                        "op": "destroy_module",
                        "code": "EIO",
                        "match": {"name": "never"},
                    }
                },
                {"start": True},
                {"expect_state": {}},
            ],
            kernel={
                "links": {"3": "core"},
                "routes": [{"dst": "0.0.0.0/0", "gw": "10.2.0.1", "oif": 3}],
            },
        )
        mismatches, _ = runner.run_trace(trace, PythonAdapter, errors)
        self.assertEqual(
            {"ops after the last expect", "bess_error never triggered"},
            {m.kind for m in mismatches},
        )

    def test_kernel_refuses_events_it_could_not_emit(self):
        kernel = runner.FakeKernel({"links": {"3": "core"}})
        with self.assertRaises(ValueError):
            kernel.route_del({"dst": "10.0.0.0/8"})
        with self.assertRaises(ValueError):
            kernel.neigh_del({"dst": "10.2.0.1", "ifindex": 3})

    # -- matching

    def test_refused_op_is_not_effective(self):
        bess, recorder = self._bess()
        with self.assertRaises(errors.Error):
            bess.destroy_module("nope")
        self.assertEqual(
            [["destroy_module", "nope"], ["error", "ENOENT"]], recorder.all_ops
        )
        self.assertIsNotNone(
            runner.compare_ops(
                [["destroy_module", "nope"]], recorder.all_ops, False, False
            )
        )
        self.assertIsNone(
            runner.compare_ops(
                [["destroy_module", "nope"], ["error", "ENOENT"]],
                recorder.all_ops,
                False,
                True,
            )
        )

    def test_wildcard_assignment_backtracks(self):
        expected = [["connect", "a", "*", "b", 0], ["connect", "a", 1, "b", 0]]
        actual = [["connect", "a", 1, "b", 0], ["connect", "a", 2, "b", 0]]
        self.assertIsNone(runner.compare_ops(expected, actual, False, False))

    def test_unordered_mismatch_reports_both_sides(self):
        expected = [["destroy_module", "x"], ["destroy_module", "x"]]
        actual = [["destroy_module", "x"], ["destroy_module", "y"]]
        self.assertEqual(
            (
                {"missing": [["destroy_module", "x"]]},
                {"extra": [["destroy_module", "y"]]},
            ),
            runner.compare_ops(expected, actual, False, False),
        )

    def test_ordered_mismatch_names_the_first_divergence(self):
        expected = [["pause"], ["resume"], ["probe", "a"]]
        actual = [["pause"], ["resume"], ["probe", "b"]]
        result = runner.compare_ops(expected, actual, True, True)
        self.assertEqual(2, result[0]["first_divergence"])

    def test_strict_does_not_imply_ordered(self):
        actual = [["pause"], ["resume"]]
        self.assertIsNone(
            runner.compare_ops([["resume"], ["pause"]], actual, False, True)
        )
        self.assertIsNotNone(
            runner.compare_ops([["resume"], ["pause"]], actual, True, True)
        )

    def test_reads_do_not_count_unless_strict(self):
        actual = [
            ["list_modules"],
            ["get_module_info", "coreRoutes"],
            ["pause"],
            ["resume"],
        ]
        self.assertIsNone(runner.compare_ops([], actual, False, False))
        self.assertIsNotNone(runner.compare_ops([], actual, False, True))

    def test_many_identical_ops_match_quickly(self):
        expected = [["probe", "10.2.0.1"]] * 500
        actual = [["probe", "10.2.0.1"]] * 499
        started = time.perf_counter()
        result = runner.compare_ops(expected, actual, False, False)
        self.assertLess(time.perf_counter() - started, 5.0)
        self.assertEqual(({"missing": [["probe", "10.2.0.1"]]}, {"extra": []}), result)
        self.assertIsNotNone(runner.compare_ops(expected, actual, True, False))

    def test_allowed_op_counts_once_in_either_mode(self):
        allow = [["probe", "x"]]
        two = [["probe", "x"], ["probe", "x"]]
        for ordered in (False, True):
            self.assertIsNone(runner.compare_ops([], two[:1], ordered, False, allow))
            self.assertIsNotNone(runner.compare_ops([], two, ordered, False, allow))

    def test_expected_and_allowed_are_matched_jointly(self):
        cases = (
            ([["connect", "a", 1, "b", 0]], [["connect", "a", "*", "b", 0]]),
            ([["connect", "a", "*", "b", 0]], [["connect", "a", 1, "b", 0]]),
        )
        for expected, allow in cases:
            for actual in (
                [["connect", "a", 1, "b", 0], ["connect", "a", 2, "b", 0]],
                [["connect", "a", 2, "b", 0], ["connect", "a", 1, "b", 0]],
            ):
                self.assertIsNone(
                    runner.compare_ops(expected, actual, False, False, allow)
                )
                self.assertIsNone(
                    runner.compare_ops(expected, actual, True, False, allow)
                )

    def test_recorded_state_overrides_only_its_keys(self):
        trace = self._trace(
            [
                {"start": True},
                {"expect": []},
                {
                    "expect_state": {
                        "modules": {"nope": {}},
                        "forwarding": {"coreRoutes": {"0.0.0.0/0": "unwired"}},
                    },
                    "expect_state_python": {"modules": {}, "absent": ["nope"]},
                    "because": "a test",
                },
            ]
        )
        mismatches, _ = runner.run_trace(
            trace, PythonAdapter, errors, use_python_expectations=True
        )
        self.assertEqual(
            ["expect_state_python forwarding coreRoutes"], [m.kind for m in mismatches]
        )

    def test_state_key_satisfied_understands_partial_module_specs(self):
        spec = {
            "modules": {"m": {}},
            "absent": ["x"],
            "forwarding": {"coreRoutes": {"0.0.0.0/0": "drop"}},
        }
        recorded = {
            "modules": {
                "m": {"mclass": "Update", "arg": {"dst_mac": "aa:aa:aa:aa:aa:aa"}}
            },
            "absent": ["x"],
        }
        self.assertTrue(runner.state_key_satisfied(spec, "modules", recorded))
        self.assertFalse(
            runner.state_key_satisfied(
                spec, "modules", {"modules": {}, "absent": ["m", "x"]}
            )
        )
        self.assertFalse(
            runner.state_key_satisfied(
                spec,
                "forwarding",
                {"forwarding": {"coreRoutes": {"0.0.0.0/0": "unwired"}}},
            )
        )

    def test_sleep_under_pause_is_bounded(self):
        ops = [
            ["pause"],
            ["sleep", 2],
            ["resume"],
            ["sleep", 3],
            ["pause"],
            ["error", "RPCError"],
            ["sleep", 2],
        ]
        self.assertEqual(2.0, runner.paused_sleep(ops))
        self.assertIsNotNone(
            runner.compare_checkpoint({"expect": [], "max_paused_sleep": 0}, ops)
        )
        self.assertIsNone(runner.compare_checkpoint({"expect": []}, ops))

    # -- the fake daemon

    def test_route_table_change_needs_the_pause(self):
        bess, _ = self._bess()
        arg = {"prefix": "10.0.0.0", "prefix_len": 8, "gate": 0}
        with self.assertRaises(errors.Error) as raised:
            bess.run_module_command("coreRoutes", "add", "IPLookupCommandAddArg", arg)
        self.assertEqual(16, raised.exception.code)  # EBUSY
        bess.pause_all()
        bess.run_module_command("coreRoutes", "add", "IPLookupCommandAddArg", arg)
        self.assertEqual(
            "unwired", bess.state()["forwarding"]["coreRoutes"]["10.0.0.0/8"]
        )

    def test_worker_check_is_per_module(self):
        bess, _ = self._bess()
        bess.create_module(
            "Update", "u", {"fields": [{"offset": 0, "size": 6, "value": 1}]}
        )
        # Nothing reaches "u" yet, so its thread-unsafe command runs unpaused.
        bess.run_module_command("u", "clear", "EmptyArg", {})
        bess.connect_modules("coreRoutes", "u", 0, 0)
        with self.assertRaises(errors.Error) as raised:
            bess.run_module_command("u", "clear", "EmptyArg", {})
        self.assertEqual(16, raised.exception.code)

    def test_daemon_rules(self):
        bess, _ = self._bess()
        with self.assertRaises(errors.Error) as raised:
            bess.create_module("Merge", "coreMerge")
        self.assertEqual(17, raised.exception.code)  # EEXIST
        with self.assertRaises(errors.Error) as raised:
            bess.destroy_module("nope")
        self.assertEqual(2, raised.exception.code)  # ENOENT
        with self.assertRaises(errors.Error) as raised:
            bess.connect_modules("coreMerge", "coreSrcEther", 0, 0)
        self.assertEqual(16, raised.exception.code)  # EBUSY: gate already wired
        with self.assertRaises(errors.Error) as raised:
            bess.run_module_command("coreMerge", "add", "EmptyArg", {})
        self.assertEqual(95, raised.exception.code)  # ENOTSUP
        gate = bess.get_module_info("coreMerge").ogates[0]
        self.assertEqual((0, "coreSrcEther", 0), (gate.ogate, gate.name, gate.igate))

    def test_responses_are_shaped_like_pybess(self):
        bess, _ = self._bess()
        names = {m.name: m.mclass for m in bess.list_modules().modules}
        self.assertEqual("IPLookup", names["coreRoutes"])
        info = bess.get_module_info("coreMerge")
        self.assertEqual("Merge", info.mclass)
        self.assertEqual(
            [(0, "coreSrcEther", 0)], [(g.ogate, g.name, g.igate) for g in info.ogates]
        )
        self.assertEqual(0, info.error.code)

    def test_update_fields_drive_forwarding(self):
        bess, _ = self._bess()
        bess.create_module(
            "Update",
            "u",
            {"fields": [{"offset": 0, "size": 6, "value": 0xAABBCC000002}]},
        )
        bess.connect_modules("u", "coreMerge", 0, 0)
        bess.pause_all()
        bess.run_module_command(
            "coreRoutes",
            "add",
            "IPLookupCommandAddArg",
            {"prefix": "0.0.0.0", "prefix_len": 0, "gate": 0},
        )
        bess.connect_modules("coreRoutes", "u", 0, 0)
        bess.run_module_command("u", "clear", "EmptyArg", {})
        bess.run_module_command(
            "u",
            "add",
            "UpdateArg",
            {"fields": [{"offset": 0, "size": 6, "value": 0xAABBCC000022}]},
        )
        bess.resume_all()
        self.assertEqual(
            {"dst_mac": "aa:bb:cc:00:00:22", "to": "coreMerge"},
            bess.state()["forwarding"]["coreRoutes"]["0.0.0.0/0"],
        )

    def test_update_value_wider_than_its_size_is_truncated(self):
        # update.cc:90-97: the width check cannot fire; the low bytes are written.
        bess, _ = self._bess()
        bess.create_module(
            "Update",
            "u",
            {"fields": [{"offset": 0, "size": 6, "value": 0x01AABBCC000002}]},
        )
        self.assertEqual("aa:bb:cc:00:00:02", bess.modules["u"].dst_mac())

    def test_overlapping_update_writes_apply_in_order(self):
        fields = [
            {"offset": 0, "size": 6, "value": 0xAABBCC000002},
            {"offset": 5, "size": 1, "value": 0x22},
        ]
        self.assertEqual("aa:bb:cc:00:00:22", runner._dst_mac_from_fields(fields))
        self.assertIsNone(runner._dst_mac_from_fields(fields[1:]))

    def test_update_field_limit_applies_at_creation(self):
        bess, _ = self._bess()
        fields = [{"offset": 6 + i, "size": 1, "value": 0} for i in range(17)]
        with self.assertRaises(errors.Error) as raised:
            bess.create_module("Update", "toomany", {"fields": fields})
        self.assertEqual(22, raised.exception.code)  # EINVAL
        bess.create_module("Update", "justenough", {"fields": fields[:16]})

    def test_gate_limits_on_connect(self):
        bess, _ = self._bess()
        bess.create_module(
            "Update", "u", {"fields": [{"offset": 0, "size": 6, "value": 1}]}
        )
        with self.assertRaises(errors.Error) as raised:
            bess.connect_modules("coreRoutes", "u", 0, 1)  # Update has one input gate
        self.assertEqual(22, raised.exception.code)
        with self.assertRaises(errors.Error) as raised:
            bess.connect_modules("corebad_route", "u", 0, 0)  # Sink has no output gate
        self.assertEqual(22, raised.exception.code)
        bess.connect_modules("coreRoutes", "u", 5000, 0)  # IPLookup has 8192

    def test_ip_lookup_drop_gate(self):
        bess, _ = self._bess()
        bess.pause_all()
        bess.run_module_command(
            "coreRoutes",
            "add",
            "IPLookupCommandAddArg",
            {"prefix": "10.0.0.0", "prefix_len": 8, "gate": runner.DROP_GATE},
        )
        with self.assertRaises(errors.Error) as raised:
            bess.run_module_command(
                "coreRoutes",
                "add",
                "IPLookupCommandAddArg",
                {"prefix": "11.0.0.0", "prefix_len": 8, "gate": runner.DROP_GATE + 1},
            )
        self.assertEqual(22, raised.exception.code)  # EINVAL
        bess.run_module_command(
            "coreRoutes",
            "delete",
            "IPLookupCommandDeleteArg",
            {"prefix": "0.0.0.0", "prefix_len": 0},
        )
        state = bess.state()
        self.assertEqual("drop", state["forwarding"]["coreRoutes"]["10.0.0.0/8"])
        self.assertEqual(runner.DROP_GATE, state["routes"]["coreRoutes"]["0.0.0.0/0"])
        self.assertEqual("drop", state["forwarding"]["coreRoutes"]["0.0.0.0/0"])

    def test_restart_breaks_the_channel_until_reconnected(self):
        bess, recorder = self._bess()
        with self.assertRaises(errors.APIError):
            bess.connect()  # already connected
        bess.restart()
        with self.assertRaises(errors.RPCError):
            bess.pause_all()
        with self.assertRaises(errors.RPCError):
            bess.connect()  # pybess: a broken channel is let go of and the call fails
        bess.connect()  # the next attempt succeeds
        bess.pause_all()
        self.assertEqual(
            [
                ["reconnect"],
                ["pause"],
                ["error", "RPCError"],
                ["reconnect"],
                ["error", "RPCError"],
                ["reconnect"],
                ["pause"],
            ],
            recorder.all_ops,
        )
        bess.restart()
        bess.disconnect()  # an explicit disconnect makes the first connect succeed
        bess.connect()
        self.assertTrue(bess.is_connected())

    def test_daemon_down_keeps_refusing_until_up(self):
        bess, _ = self._bess()
        bess.down()
        with self.assertRaises(errors.RPCError):
            bess.connect()  # lets the broken channel go
        with self.assertRaises(errors.RPCError):
            bess.connect()  # still down
        bess.up()
        bess.connect()
        self.assertTrue(bess.is_connected())

    def test_kernel_tables_are_separate(self):
        kernel = runner.FakeKernel({"links": {"3": "core"}})
        kernel.route_add({"dst": "10.0.0.0/8", "gw": "10.2.0.1", "oif": 3})
        kernel.route_add(
            {"dst": "10.0.0.0/8", "gw": "10.2.0.9", "oif": 3, "table": 100}
        )
        self.assertEqual(2, len(kernel.routes))
        kernel.route_del({"dst": "10.0.0.0/8", "table": 100})
        self.assertEqual([254], [r.get("table", 254) for r in kernel.routes])
        kernel.route_add({"dst": "10.0.0.0/8", "gw": "10.2.0.2", "oif": 3})  # replace
        self.assertEqual(["10.2.0.2"], [r["gw"] for r in kernel.routes])

    def test_kernel_dump_filters_by_family(self):
        kernel = runner.FakeKernel(
            {
                "links": {"3": "core"},
                "routes": [
                    {"dst": "::/0", "gw": "fe80::1", "oif": 3},
                    {"dst": "0.0.0.0/0", "gw": "10.2.0.1", "oif": 3},
                ],
            }
        )
        self.assertEqual([2], [m["family"] for m in kernel.route_dump(2)])
        self.assertEqual([10, 2], [m["family"] for m in kernel.route_dump()])

    def test_ticks_accumulate_toward_the_probe_deadline(self):
        trace = self._trace(
            [
                {"start": True},
                {"expect": [["probe", "10.2.0.1"], ["probe", "10.2.0.1"]]},
                {"tick": 5},
                {"expect": []},
                {"tick": 5},
                {"expect": [["probe", "10.2.0.1"]]},
                {"tick": 25},
                {"expect": [["probe", "10.2.0.1"], ["probe", "10.2.0.1"]]},
            ],
            kernel={
                "links": {"3": "core"},
                "routes": [{"dst": "0.0.0.0/0", "gw": "10.2.0.1", "oif": 3}],
            },
        )
        mismatches, _ = runner.run_trace(trace, PythonAdapter, errors)
        self.assertEqual([], mismatches, "\n" + "\n".join(str(m) for m in mismatches))

    def test_ping_pass_due_during_a_handler_runs_after_it(self):
        # Five refused connects sleep 10 s inside the handler; the ping thread
        # would take its pass as soon as the handler releases the lock.
        trace = self._trace(
            [
                {"start": True},
                {"expect": [["probe", "10.2.0.9"], ["probe", "10.2.0.9"]]},
                {
                    "neigh_add": {
                        "dst": "10.2.0.1",
                        "lladdr": "aa:bb:cc:00:00:02",
                        "ifindex": 3,
                    }
                },
            ]
            + [
                {
                    "bess_error": {
                        "op": "connect",
                        "code": "EBUSY",
                        "match": {"m1": "coreRoutes"},
                    }
                }
            ]
            * 5
            + [
                {"route_add": {"dst": "172.16.0.0/16", "gw": "10.2.0.1", "oif": 3}},
                {
                    "expect": [
                        [
                            "module_command",
                            "coreRoutes",
                            "add",
                            {"prefix": "172.16.0.0", "prefix_len": 16, "gate": 0},
                        ],
                        [
                            "create_module",
                            "coreDstMACAABBCC000002",
                            "Update",
                            {"dst_mac": "aa:bb:cc:00:00:02"},
                        ],
                        ["probe", "10.2.0.9"],
                    ]
                },
            ],
            kernel={
                "links": {"3": "core"},
                "routes": [{"dst": "0.0.0.0/0", "gw": "10.2.0.9", "oif": 3}],
            },
        )
        mismatches, _ = runner.run_trace(trace, PythonAdapter, errors)
        self.assertEqual([], mismatches, "\n" + "\n".join(str(m) for m in mismatches))

    def test_failed_adapter_construction_leaves_no_patches(self):
        from unittest.mock import patch

        import conf.route_control as rc

        recorder = runner.Recorder()
        kernel = runner.FakeKernel({"links": {"3": "core"}})
        with (
            patch.object(rc, "RouteController", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            PythonAdapter(
                kernel,
                runner.FakeBess(recorder, errors, ["core"]),
                runner.VirtualClock(recorder),
                recorder,
                ["core"],
            )
        self.assertIs(time, rc.time)
        self.assertFalse(logging.getLogger(rc.__name__).disabled)


if __name__ == "__main__":
    unittest.main()
