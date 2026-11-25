"""Regression tests for the console's synthetic polling replays."""

import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from backend.server import ConsoleHandler
from backend.simulation import SCENARIOS, run_scenario
from controller.ryu_app.adaptive_poller import AdaptivePoller


class TestPollingSimulation(unittest.TestCase):
    def test_runs_are_repeatable_and_use_their_own_sample_timestamps(self):
        for key in SCENARIOS:
            with self.subTest(scenario=key):
                result = run_scenario(key)
                self.assertEqual(result, run_scenario(key))
                for strategy in ("fixed", "adaptive"):
                    run = result[strategy]
                    steps = run["steps"]
                    self.assertEqual(run["completed_polls"], len(steps))
                    self.assertIsNone(steps[0]["packet_rate"])
                    self.assertLessEqual(steps[-1]["reply_at_s"], result["duration_s"])
                    for previous, current in zip(steps, steps[1:]):
                        self.assertAlmostEqual(
                            current["sample_at_s"], previous["reply_at_s"] + previous["next_interval_s"]
                        )

    def test_burst_enters_surge_then_cools_down(self):
        result = run_scenario("workload-burst")
        self.assertGreater(result["adaptive"]["completed_polls"], result["fixed"]["completed_polls"])
        modes = [step["mode"] for step in result["adaptive"]["steps"]]
        self.assertIn("surge", modes)
        self.assertIn("cooldown", modes)
        self.assertEqual(modes[-1], "baseline")
        self.assertTrue(all(step["next_interval_s"] == 2.0 for step in result["fixed"]["steps"]))

    def test_steady_load_produces_same_measurements(self):
        result = run_scenario("steady-load")
        self.assertEqual(result["adaptive"]["backpressure_cycles"], 0)
        self.assertEqual(
            [{**step, "mode": "fixed"} for step in result["adaptive"]["steps"]], result["fixed"]["steps"]
        )

    def test_slow_switch_triggers_adaptive_backoff(self):
        result = run_scenario("slow-switch")
        self.assertGreater(result["adaptive"]["backpressure_cycles"], 0)
        self.assertEqual(result["fixed"]["backpressure_cycles"], 0)
        steps = result["adaptive"]["steps"]
        backed_off = [step for step in steps if step["mode"] == "backpressure"]
        self.assertTrue(all(step["next_interval_s"] > 2 for step in backed_off))
        self.assertEqual(steps[-1]["mode"], "baseline")

    def test_counter_restart_marks_an_invalid_interval_and_recovers(self):
        result = run_scenario("counter-restart")
        for strategy in ("fixed", "adaptive"):
            steps = result[strategy]["steps"]
            reset_index, = (index for index, step in enumerate(steps) if step["reset_detected"])
            self.assertIsNone(steps[reset_index]["packet_rate"])
            self.assertAlmostEqual(steps[reset_index + 1]["packet_rate"], 90, delta=0.5)

    def test_healthy_reply_clears_backoff_in_baseline_and_surge(self):
        for initial_rate, recovered_interval in ((100, 2.0), (1500, 0.5)):
            with self.subTest(initial_rate=initial_rate):
                poller = AdaptivePoller()
                poller.evaluate_cycle(initial_rate, False, 0.04)
                self.assertEqual(poller.evaluate_cycle(initial_rate, False, 1.5), 3.0)
                self.assertEqual(poller.evaluate_cycle(100, False, 0.04), recovered_interval)
                self.assertFalse(poller.get_state().backpressure_active)


class TestSimulationAPI(unittest.TestCase):
    def get(self, path, host="127.0.0.1:8080"):
        class QuietHandler(ConsoleHandler):
            def log_message(self, *_):
                pass

        socket = Mock()
        socket.makefile.return_value = io.BytesIO(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        QuietHandler(socket, ("127.0.0.1", 1), SimpleNamespace(server_port=8080))
        response = b"".join(call.args[0] for call in socket.sendall.call_args_list)
        headers, _, body = response.partition(b"\r\n\r\n")
        return int(headers.split()[1]), json.loads(body)

    def test_catalog_and_run_are_available_without_models_or_database(self):
        status, catalog = self.get("/api/simulations")
        self.assertEqual(status, 200)
        self.assertEqual({scenario["id"] for scenario in catalog["scenarios"]}, set(SCENARIOS))
        for scenario in catalog["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                status, result = self.get(f"/api/simulations/{scenario['id']}")
                self.assertEqual(status, 200)
                self.assertEqual(result, run_scenario(scenario["id"]))

    def test_invalid_route_and_host_return_json_errors(self):
        self.assertEqual(self.get("/api/simulations/unknown")[0], 404)
        self.assertEqual(self.get("/api/simulations", host="example.test")[0], 403)
