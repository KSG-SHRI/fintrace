"""Offline regression tests for cutoff, integrity, and evidence reporting."""

import copy
import json
import unittest
from pathlib import Path

from fintrace import reconstruct, seal, verify


DATA = json.loads((Path(__file__).parent / "examples/synthetic_incident.json").read_text())
CUTOFF = "2025-04-03T14:30:00Z"


class FintraceTests(unittest.TestCase):
    def test_future_record_excluded_from_every_stage(self):
        bundle = seal(DATA["records"], CUTOFF)
        self.assertEqual(bundle["rejected_future_ids"], ["future1"])
        report = reconstruct(bundle, "XYZ", ["PEER1", "PEER2"])
        self.assertNotIn("future1", [e["id"] for e in report["timeline"]])
        self.assertEqual(report["target_bar_id"], "x6")
        self.assertEqual(len(report["cross_asset_edges"]), 2)
        self.assertLess(report["return_pct"], -7)

    def test_late_publication_excluded_even_if_event_is_earlier(self):
        record = copy.deepcopy(DATA["records"][0])
        record["id"] = "late"
        record["available_at"] = "2025-04-03T14:31:00Z"
        bundle = seal(DATA["records"] + [record], CUTOFF)
        self.assertIn("late", bundle["rejected_future_ids"])

    def test_tampering_and_wrong_key_fail(self):
        signed = seal(DATA["records"], CUTOFF, b"research-key")
        self.assertTrue(verify(signed, b"research-key"))
        self.assertFalse(verify(signed, b"wrong-key"))
        edited = copy.deepcopy(signed)
        edited["records"][0]["close"] = 999
        self.assertFalse(verify(edited, b"research-key"))

    def test_naive_timestamp_rejected(self):
        record = copy.deepcopy(DATA["records"][0])
        record["event_at"] = "2025-04-03T14:25:00"
        with self.assertRaises(ValueError):
            seal([record], CUTOFF)

    def test_sparse_history_does_not_invent_anomaly_score(self):
        records = [r for r in DATA["records"] if r["id"] in {"x5", "x6"}]
        report = reconstruct(seal(records, CUTOFF), "XYZ", [])
        self.assertIsNone(report["return_z"])
        self.assertIsNone(report["volume_z"])


if __name__ == "__main__":
    unittest.main()
