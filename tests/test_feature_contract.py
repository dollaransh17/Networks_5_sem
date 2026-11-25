"""
tests/test_feature_contract.py

Unit tests for the Frozen Feature Contract & Extractor:
- Verifies strict order and array shape of FEATURE_NAMES.
- Verifies feature extraction using the PDF worked example values.
- Verifies handling of switch reboots / counter resets (is_valid=False).
"""

import unittest
import numpy as np

from ai.features.feature_contract import (
    FEATURE_NAMES,
    FeatureExtractor,
    FlowFeatureVector
)
from ai.features.counter_rates import FlowCounterSample


class TestFeatureContract(unittest.TestCase):

    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_feature_names_order(self):
        expected = [
            "packet_rate",
            "byte_rate",
            "avg_packet_size",
            "packet_count",
            "byte_count",
            "flow_duration_sec",
        ]
        self.assertEqual(FEATURE_NAMES, expected)

    def test_extraction_worked_example(self):
        # 0.5s interval: 300 pkts, 24,000 bytes -> 600 pkts/s, 48,000 B/s, avg size 80 B/pkt
        s1 = FlowCounterSample(timestamp_s=10.0, packet_count=1000, byte_count=80000)
        s2 = FlowCounterSample(timestamp_s=10.5, packet_count=1300, byte_count=104000)

        vec: FlowFeatureVector = self.extractor.extract(s1, s2, flow_duration_sec=10.5)

        self.assertTrue(vec.is_valid)
        self.assertFalse(vec.reset_detected)
        self.assertAlmostEqual(vec.features["packet_rate"], 600.0)
        self.assertAlmostEqual(vec.features["byte_rate"], 48000.0)
        self.assertAlmostEqual(vec.features["avg_packet_size"], 80.0)
        self.assertEqual(vec.features["packet_count"], 1300.0)
        self.assertEqual(vec.features["byte_count"], 104000.0)
        self.assertEqual(vec.features["flow_duration_sec"], 10.5)

        arr = vec.to_array()
        self.assertIsInstance(arr, np.ndarray)
        self.assertEqual(arr.shape, (6,))
        self.assertAlmostEqual(arr[0], 600.0)

    def test_counter_reset_handling(self):
        s1 = FlowCounterSample(timestamp_s=10.0, packet_count=5000, byte_count=200000)
        # Drop in counter = switch reset
        s2 = FlowCounterSample(timestamp_s=12.0, packet_count=10, byte_count=800)

        vec = self.extractor.extract(s1, s2, flow_duration_sec=2.0)
        self.assertFalse(vec.is_valid)
        self.assertTrue(vec.reset_detected)


if __name__ == '__main__':
    unittest.main()

