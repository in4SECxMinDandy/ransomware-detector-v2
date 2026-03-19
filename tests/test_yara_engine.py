"""
test_yara_engine.py
===================
Unit tests for core/yara_engine.py
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.yara_engine import (
    YaraEngine,
    YaraMatch,
    PYTHON_SIGNATURES,
    get_yara_engine,
)


class TestYaraMatch:
    def test_yara_match_creation(self):
        """YaraMatch should store all attributes."""
        match = YaraMatch("TestRule", "Test description", "CRITICAL", "TestFamily")
        assert match.rule_name == "TestRule"
        assert match.description == "Test description"
        assert match.severity == "CRITICAL"
        assert match.family == "TestFamily"

    def test_yara_match_to_dict(self):
        """to_dict should return all fields."""
        match = YaraMatch("Rule1", "Desc", "HIGH", "Family1")
        d = match.to_dict()
        assert d["rule_name"] == "Rule1"
        assert d["severity"] == "HIGH"
        assert d["family"] == "Family1"

    def test_yara_match_repr(self):
        """__repr__ should be informative."""
        match = YaraMatch("Rule1", "Desc", "HIGH", "Family1")
        assert "Rule1" in repr(match)
        assert "HIGH" in repr(match)


class TestYaraEngine:
    def test_engine_always_available(self):
        """Engine should always be available (even without yara-python)."""
        engine = YaraEngine()
        assert engine.is_available() is True

    def test_get_rules_count(self):
        """get_rules_count should return PYTHON_SIGNATURES count."""
        engine = YaraEngine()
        assert engine.get_rules_count() == len(PYTHON_SIGNATURES)

    def test_scan_nonexistent_file_returns_empty(self):
        """Scanning non-existent file should return empty list."""
        engine = YaraEngine()
        matches = engine.scan_file("/nonexistent/file.exe")
        assert matches == []

    def test_engine_type_defined(self):
        """get_engine_type should return a string."""
        engine = YaraEngine()
        t = engine.get_engine_type()
        assert isinstance(t, str)
        assert t in ("yara-python", "Python fallback")

    def test_apply_yara_boost_empty(self):
        """Empty matches should return original probability."""
        engine = YaraEngine()
        prob, reason = engine.apply_yara_boost(0.5, [])
        assert prob == 0.5
        assert reason == ""

    def test_apply_yara_boost_critical(self):
        """CRITICAL match should boost probability by 0.30."""
        engine = YaraEngine()
        match = YaraMatch("Test", "Test", "CRITICAL", "Test")
        prob, reason = engine.apply_yara_boost(0.50, [match])
        assert prob == 0.80  # 0.50 + 0.30
        assert "CRITICAL" in reason

    def test_apply_yara_boost_high(self):
        """HIGH match should boost probability by 0.15."""
        engine = YaraEngine()
        match = YaraMatch("Test", "Test", "HIGH", "Test")
        prob, _ = engine.apply_yara_boost(0.50, [match])
        assert prob == 0.65  # 0.50 + 0.15

    def test_apply_yara_boost_medium(self):
        """MEDIUM match should boost probability by 0.05."""
        engine = YaraEngine()
        match = YaraMatch("Test", "Test", "MEDIUM", "Test")
        prob, _ = engine.apply_yara_boost(0.50, [match])
        assert prob == 0.55  # 0.50 + 0.05

    def test_apply_yara_boost_capped_at_099(self):
        """Boosted probability should be capped at 0.99."""
        engine = YaraEngine()
        match = YaraMatch("Test", "Test", "CRITICAL", "Test")
        prob, _ = engine.apply_yara_boost(0.90, [match])
        assert prob == 0.99  # min(0.90+0.30, 0.99)

    def test_apply_yara_boost_max_severity_used(self):
        """Only the highest severity boost should be applied."""
        engine = YaraEngine()
        critical = YaraMatch("C", "C", "CRITICAL", "F")
        medium   = YaraMatch("M", "M", "MEDIUM", "F")
        prob, reason = engine.apply_yara_boost(0.50, [critical, medium])
        # Uses CRITICAL boost (0.30), not both
        assert prob == 0.80


class TestPythonSignatures:
    def test_all_signatures_have_required_fields(self):
        """Every signature should have required keys."""
        required = {"name", "description", "severity", "family",
                    "byte_patterns", "ext_patterns", "min_matches"}
        for sig in PYTHON_SIGNATURES:
            assert required.issubset(sig.keys()), f"Missing keys in {sig.get('name')}"

    def test_all_signatures_have_valid_severity(self):
        """Every signature should have a valid severity."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for sig in PYTHON_SIGNATURES:
            assert sig["severity"] in valid, f"Invalid severity: {sig['name']}"

    def test_generic_ransom_note_min_matches(self):
        """Generic_RansomNote should require at least 3 keyword matches."""
        for sig in PYTHON_SIGNATURES:
            if sig["name"] == "Generic_RansomNote":
                assert sig["min_matches"] >= 3

    def test_family_coverage(self):
        """All major ransomware families should be covered."""
        families = {sig["family"] for sig in PYTHON_SIGNATURES}
        expected_families = {
            "WannaCry", "LockBit", "BlackCat", "Ryuk", "Cl0p",
            "REvil", "Conti", "Play", "Rhysida", "Akira",
            "BianLian", "Medusa", "Qilin", "Generic", "Injection",
        }
        for fam in expected_families:
            assert fam in families, f"Missing family: {fam}"


class TestBuiltinRulesInfo:
    def test_get_builtin_rules_info(self):
        """get_builtin_rules_info should return info for all signatures."""
        engine = YaraEngine()
        info = engine.get_builtin_rules_info()
        assert len(info) == len(PYTHON_SIGNATURES)
        for item in info:
            assert "name" in item
            assert "severity" in item


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
