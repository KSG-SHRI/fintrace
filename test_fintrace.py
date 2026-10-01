"""Offline regression tests for cutoff, integrity, and evidence reporting."""

import copy
import json
import unittest
from pathlib import Path

from fintrace import reconstruct, seal, verify, verify_incident


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

    def test_offsets_sort_by_actual_instant_not_timestamp_text(self):
        records = [
            {"id": "early", "kind": "bar", "ticker": "XYZ", "event_at": "2025-04-03T16:29:00+02:00",
             "available_at": "2025-04-03T14:29:00Z", "source": "synthetic", "close": 100, "volume": 1},
            {"id": "late", "kind": "bar", "ticker": "XYZ", "event_at": "2025-04-03T10:30:00-04:00",
             "available_at": "2025-04-03T14:30:00Z", "source": "synthetic", "close": 90, "volume": 2},
        ]
        report = reconstruct(seal(records, CUTOFF), "XYZ", [])
        self.assertEqual(report["target_bar_id"], "late")
        self.assertEqual(report["return_pct"], -10)

    def test_peer_requires_both_synchronized_endpoints(self):
        records = [r for r in DATA["records"] if r["id"] in {"x5", "x6", "p2"}]
        old_peer = copy.deepcopy(next(r for r in DATA["records"] if r["id"] == "p1"))
        old_peer["event_at"] = old_peer["available_at"] = "2025-04-03T14:28:00Z"
        report = reconstruct(seal(records + [old_peer], CUTOFF), "XYZ", ["PEER1"])
        self.assertEqual(report["peer_returns_pct"], {})
        self.assertIsNone(report["peer_median_pct"])

    def test_publication_after_move_is_not_retroactive_evidence(self):
        late = {"id": "post_move", "kind": "news", "ticker": "XYZ",
                "event_at": "2025-04-03T14:27:00Z", "available_at": "2025-04-03T14:30:30Z",
                "source": "synthetic", "summary": "Published after the last bar"}
        bundle = seal(DATA["records"] + [late], "2025-04-03T14:31:00Z")
        report = reconstruct(bundle, "XYZ", [])
        self.assertNotIn("post_move", [event["id"] for event in report["timeline"]])

    def test_duplicate_ids_even_when_one_is_future(self):
        future = copy.deepcopy(DATA["records"][0])
        future["event_at"] = future["available_at"] = "2025-04-03T14:31:00Z"
        with self.assertRaisesRegex(ValueError, "duplicate record id"):
            seal([DATA["records"][0], future], CUTOFF)

    def test_duplicate_bar_time_and_nonfinite_values_rejected(self):
        duplicate = copy.deepcopy(DATA["records"][0])
        duplicate["id"] = "other_id"
        with self.assertRaisesRegex(ValueError, "duplicate bar timestamp"):
            reconstruct(seal([duplicate, DATA["records"][0], DATA["records"][1]], CUTOFF), "XYZ", [])
        for invalid in (float("nan"), float("inf"), True, -1):
            with self.subTest(invalid=invalid):
                records = copy.deepcopy([DATA["records"][0], DATA["records"][1]])
                records[0]["close"] = invalid
                with self.assertRaises(ValueError):
                    reconstruct(seal(records, CUTOFF), "XYZ", [])

    def test_edge_references_both_price_endpoints(self):
        report = reconstruct(seal(DATA["records"], CUTOFF), "XYZ", ["PEER1"])
        self.assertEqual(report["cross_asset_edges"][0]["evidence_ids"], ["x5", "x6", "p1", "p2"])

    def test_incident_replay_detects_report_tampering(self):
        bundle = seal(DATA["records"], CUTOFF, b"research-key")
        envelope = {"bundle": bundle, "report": reconstruct(bundle, "XYZ", ["PEER1"], key=b"research-key")}
        self.assertTrue(verify_incident(envelope, b"research-key"))
        tampered = copy.deepcopy(envelope)
        tampered["report"]["assessment"] = "Definitely caused by the fictional macro bulletin."
        self.assertFalse(verify_incident(tampered, b"research-key"))
        self.assertFalse(verify_incident(envelope, b"wrong-key"))


if __name__ == "__main__":
    unittest.main()
