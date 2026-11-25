"""
tests/test_counter_rates.py

Unit tests for OVS flow counter rates calculation:
- Verifies packet_rate and byte_rate from sequential FlowCounterSamples over actual Delta t.
- Verifies switch reboot / counter reset detection (curr < prev).
- Verifies zero or sub-millisecond elapsed time handling (avoids division by zero).
- Follows worked example from PRD Section 5.2 and PDF Section 5.
"""

import unittest
from ai.features.counter_rates import (
    FlowCounterSample,
    FlowRateMetrics,
    calculate_flow_rates,
)


class TestCounterRates(unittest.TestCase):

    def test_worked_example_calculation(self):
        """
        Worked example:
        Sample 1 at t=10.0s: 1000 pkts, 80,000 bytes
        Sample 2 at t=10.5s: 1300 pkts, 104,000 bytes
        Delta t = 0.5s, Delta pkts = 300, Delta bytes = 24,000
        Expected: packet_rate = 600 pkts/s, byte_rate = 48,000 bytes/s
        """
        s1 = FlowCounterSample(timestamp_s=10.0, packet_count=1000, byte_count=80000)
        s2 = FlowCounterSample(timestamp_s=10.5, packet_count=1300, byte_count=104000)

        rates: FlowRateMetrics = calculate_flow_rates(s1, s2)

        self.assertTrue(rates.is_valid)
        self.assertFalse(rates.reset_detected)
        self.assertAlmostEqual(rates.elapsed_time_s, 0.5)
        self.assertAlmostEqual(rates.packet_rate, 600.0)
        self.assertAlmostEqual(rates.byte_rate, 48000.0)

    def test_counter_reset_detected(self):
        """When counters decrease, detects switch restart / counter reset."""
        s1 = FlowCounterSample(timestamp_s=20.0, packet_count=50000, byte_count=40000000)
        s2 = FlowCounterSample(timestamp_s=22.0, packet_count=10, byte_count=800)

        rates: FlowRateMetrics = calculate_flow_rates(s1, s2)

        self.assertFalse(rates.is_valid)
        self.assertTrue(rates.reset_detected)
        self.assertEqual(rates.packet_rate, 0.0)
        self.assertEqual(rates.byte_rate, 0.0)

    def test_zero_elapsed_time_invalid(self):
        """When elapsed time is zero or sub-millisecond, returns is_valid=False."""
        s1 = FlowCounterSample(timestamp_s=10.0, packet_count=100, byte_count=8000)
        s2 = FlowCounterSample(timestamp_s=10.0001, packet_count=110, byte_count=8800)

        rates: FlowRateMetrics = calculate_flow_rates(s1, s2, min_elapsed_s=0.001)

        self.assertFalse(rates.is_valid)
        self.assertFalse(rates.reset_detected)

    def test_none_prev_sample(self):
        """When prev sample is None, returns baseline with is_valid=False."""
        s1 = FlowCounterSample(timestamp_s=10.0, packet_count=100, byte_count=8000)
        rates: FlowRateMetrics = calculate_flow_rates(None, s1)

        self.assertFalse(rates.is_valid)
        self.assertEqual(rates.elapsed_time_s, 0.0)


if __name__ == "__main__":
    unittest.main()
