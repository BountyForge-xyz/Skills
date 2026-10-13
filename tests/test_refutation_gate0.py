#!/usr/bin/env python3
"""
Tests for Gate 0 — the deterministic self-concession scanner in
tools/refutation.py.

Run:  python3 -m unittest discover -s tests -v

Gate 0 runs BEFORE any paid model pass. It guards two invariants:
  1. A finding that concedes it has no valid victim / no profit is KILLED
     deterministically, without spending a model pass.
  2. A finding that concedes a severity-capping precondition can never be
     CONFIRMED — a later model "CONFIRMED" is clamped down to DEMOTED.
A clean finding passes through untouched (scan returns None).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.refutation import (  # noqa: E402
    scan_concessions,
    FindingVerdict,
    RefutationEngine,
    RefutationPass,
)


class ScanConcessionsTest(unittest.TestCase):

    def _verdict(self, finding):
        result = scan_concessions(finding)
        return None if result is None else result[0]

    # --- KILL concessions -------------------------------------------------
    def test_kill_self_harm_only(self):
        f = {"title": "Reentrancy", "impact": "This is self-harm only."}
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)

    def test_kill_attacker_own_funds(self):
        f = {"impact": "The attacker only loses their own funds in the process."}
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)

    def test_kill_no_external_victim(self):
        f = {"description": "There is no external victim; nobody else is affected."}
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)

    def test_kill_not_profitable(self):
        f = {"evidence": "In practice the attack is not economically viable."}
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)

    def test_kill_cost_exceeds_yield(self):
        f = {"impact": "The attack costs more gas than it yields."}
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)

    # --- DEMOTE concessions ----------------------------------------------
    def test_demote_requires_owner(self):
        f = {"description": "This requires the contract owner to call it first."}
        self.assertEqual(self._verdict(f), FindingVerdict.DEMOTED)

    def test_demote_no_funds_at_risk(self):
        f = {"impact": "There is no direct fund loss; no funds at risk."}
        self.assertEqual(self._verdict(f), FindingVerdict.DEMOTED)

    def test_demote_fee_drag(self):
        f = {"impact": "The effect is fee-drag only over many transactions."}
        self.assertEqual(self._verdict(f), FindingVerdict.DEMOTED)

    # --- clean findings pass through -------------------------------------
    def test_clean_finding_returns_none(self):
        f = {
            "title": "Unauthenticated withdrawal",
            "impact": "Any user can drain the vault with one call.",
            "evidence": "PoC transfers 10 ETH to an unrelated attacker address.",
        }
        self.assertIsNone(scan_concessions(f))

    def test_scans_list_fields(self):
        f = {"notes": ["clean note", "ultimately self-harm only here"]}
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)

    # --- KILL ranks above DEMOTE -----------------------------------------
    def test_kill_takes_priority_over_demote(self):
        f = {
            "description": "Requires the admin, and it is self-harm only anyway.",
        }
        self.assertEqual(self._verdict(f), FindingVerdict.KILLED)


class RefuteShortCircuitTest(unittest.TestCase):
    """refute() must short-circuit a KILL concession with zero model passes."""

    def test_kill_concession_short_circuits_without_model(self):
        engine = RefutationEngine(target="gate0-test.example")
        finding = {
            "finding_id": "gate0kill0001",
            "title": "Griefing",
            "impact": "Self-harm only — the attacker loses their own funds.",
        }
        # passes=5 would normally run 5 model passes; Gate 0 must run none.
        record = engine.refute(finding, model="haiku", passes=5)
        self.assertEqual(record.final_verdict, FindingVerdict.KILLED)
        self.assertEqual(record.total_passes, 1)
        self.assertEqual(record.passes[0].model, "deterministic")
        self.assertIsInstance(record.passes[0], RefutationPass)


if __name__ == "__main__":
    unittest.main()
