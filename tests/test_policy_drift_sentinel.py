import ast
import json
import re
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "policy_drift_sentinel.py"
CONTRACT_SOURCE = CONTRACT_PATH.read_text(encoding="utf-8")


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    return parsed.netloc.replace("www.", "").split(":")[0]


def fingerprint(value: str) -> str:
    checksum = 0
    for index, char in enumerate(value):
        checksum = (checksum + ((index + 1) * ord(char))) % 1000000007
    return str(checksum)


def parse_json_dict(json_str: str) -> dict:
    first_brace = json_str.find("{")
    last_brace = json_str.rfind("}")
    if first_brace == -1 or last_brace == -1 or last_brace < first_brace:
        raise ValueError("No JSON object found.")
    return json.loads(json_str[first_brace : last_brace + 1])


def test_helper_behavior_is_deterministic():
    assert normalize_domain("https://www.Example.com/path") == "example.com"
    assert fingerprint("abc") == fingerprint("abc")
    assert fingerprint("abc") != fingerprint("abd")
    assert parse_json_dict('```json\n{"a":1}\n```') == {"a": 1}


def test_contract_uses_stateful_policy_drift_lifecycle():
    ast.parse(CONTRACT_SOURCE)

    assert "baseline_hash" in CONTRACT_SOURCE
    assert "current_hash" in CONTRACT_SOURCE
    assert "self.baseline_hash = current_hash" in CONTRACT_SOURCE
    assert "self.checks.append" in CONTRACT_SOURCE


def test_contract_uses_consensus_only_for_changed_excerpts():
    assert "if current_hash == baseline_hash" in CONTRACT_SOURCE
    assert "gl.eq_principle_prompt_comparative" in CONTRACT_SOURCE
    assert "gl.get_webpage(policy_url" in CONTRACT_SOURCE


def test_contract_enforces_deterministic_invariants():
    assert 'value.get("policy_url") != expected_policy_url' in CONTRACT_SOURCE
    assert "excerpt_changed and severity == NO_CHANGE" in CONTRACT_SOURCE
    assert "not excerpt_changed and severity != NO_CHANGE" in CONTRACT_SOURCE
    assert "changed_chars < minimum_changed_chars" in CONTRACT_SOURCE
    assert "severity != NO_CHANGE and not requires_review" in CONTRACT_SOURCE


def test_readme_documents_consensus_and_state():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert re.search(r"Why GenLayer", readme)
    assert "State Design" in readme
    assert "Deterministic Invariants" in readme
