# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
import typing
from datetime import datetime
from urllib.parse import urlparse

from genlayer import *

NO_CHANGE = "NO_CHANGE"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
VALID_SEVERITIES = [NO_CHANGE, LOW, MEDIUM, HIGH]


class PolicyDriftSentinel(gl.Contract):
    watch_name: str
    policy_url: str
    allowed_domain: str
    baseline_hash: str
    baseline_excerpt: str
    minimum_changed_chars: u256
    checks: DynArray[str]
    latest_check: str

    def __init__(
        self,
        watch_name: str,
        policy_url: str,
        allowed_domain: str,
        baseline_excerpt: str,
        minimum_changed_chars: int,
    ):
        watch_name = watch_name.strip()
        policy_url = policy_url.strip()
        baseline_excerpt = _normalize_text(baseline_excerpt)
        allowed_domain = _normalize_domain(allowed_domain)
        if not watch_name:
            raise ValueError("Watch name is required.")
        if not policy_url:
            raise ValueError("Policy URL is required.")
        if not allowed_domain:
            raise ValueError("Allowed domain is required.")
        if _normalize_domain(policy_url) != allowed_domain:
            raise ValueError("Policy URL must match the allowed domain.")
        if len(baseline_excerpt) < 20:
            raise ValueError("Baseline excerpt is too short.")
        if minimum_changed_chars < 1 or minimum_changed_chars > 2000:
            raise ValueError("minimum_changed_chars must be between 1 and 2000.")

        self.watch_name = watch_name
        self.policy_url = policy_url
        self.allowed_domain = allowed_domain
        self.baseline_excerpt = baseline_excerpt
        self.baseline_hash = _fingerprint(baseline_excerpt)
        self.minimum_changed_chars = u256(minimum_changed_chars)
        self.latest_check = ""

    @gl.public.write
    def check_policy(self) -> typing.Any:
        policy_url = self.policy_url
        baseline_hash = self.baseline_hash
        baseline_excerpt = self.baseline_excerpt
        current_text = _normalize_text(gl.get_webpage(policy_url, mode="text"))
        current_excerpt = current_text[:1000]
        current_hash = _fingerprint(current_excerpt)
        changed_chars = _changed_prefix_chars(baseline_excerpt, current_excerpt)

        if current_hash == baseline_hash:
            drift = {
                "policy_url": policy_url,
                "severity": NO_CHANGE,
                "summary": "No deterministic drift detected in the tracked excerpt.",
                "changed_sections": [],
                "requires_review": False,
                "confidence": 100,
            }
        else:

            def classify_drift() -> str:
                task = f"""
You are reviewing a tracked policy or specification excerpt for semantic drift.

Policy URL:
{policy_url}

Previous tracked excerpt:
{baseline_excerpt}

Current tracked excerpt:
{current_excerpt}

Return only valid JSON with this exact schema:
{{
  "policy_url": "{policy_url}",
  "severity": "LOW | MEDIUM | HIGH",
  "summary": "one concise summary of the material change",
  "changed_sections": ["short changed clauses or topics"],
  "requires_review": true,
  "confidence": 0
}}

Rules:
- LOW means wording changed but builder-facing obligations are unlikely to change.
- MEDIUM means behavior, eligibility, limits, pricing, or required actions may have changed.
- HIGH means security, funds, access, compliance, or irreversible user impact may have changed.
- confidence must be an integer from 0 to 100.
- Do not use NO_CHANGE when the excerpts differ.
- Do not include markdown, prose, or extra keys.
                """
                result = gl.exec_prompt(task)
                result_dict = _parse_json_dict(result)
                _validate_drift(
                    result_dict,
                    policy_url,
                    current_hash != baseline_hash,
                    int(self.minimum_changed_chars),
                    changed_chars,
                )
                return _canonical_json(result_dict)

            agreed_result = gl.eq_principle_prompt_comparative(
                classify_drift,
                principle=(
                    "The `policy_url`, `severity`, and `requires_review` fields must match. "
                    "The changed sections and summary must describe differences between the excerpts."
                ),
            )
            drift = _parse_json_dict(agreed_result)
            _validate_drift(
                drift,
                policy_url,
                current_hash != baseline_hash,
                int(self.minimum_changed_chars),
                changed_chars,
            )

        record = {
            "id": len(self.checks) + 1,
            "submitter": gl.message.sender_address.as_hex,
            "watch_name": self.watch_name,
            "policy_url": policy_url,
            "baseline_hash": baseline_hash,
            "current_hash": current_hash,
            "changed_chars": changed_chars,
            "drift": drift,
            "created_at": datetime.now().astimezone().isoformat(),
        }
        record_json = _canonical_json(record)
        self.checks.append(record_json)
        self.latest_check = record_json
        if drift["severity"] != NO_CHANGE:
            self.baseline_hash = current_hash
            self.baseline_excerpt = current_excerpt
        return record

    @gl.public.view
    def get_watch(self) -> dict:
        return {
            "watch_name": self.watch_name,
            "policy_url": self.policy_url,
            "allowed_domain": self.allowed_domain,
            "baseline_hash": self.baseline_hash,
            "minimum_changed_chars": self.minimum_changed_chars,
        }

    @gl.public.view
    def get_check_count(self) -> int:
        return len(self.checks)

    @gl.public.view
    def get_latest_check(self) -> typing.Any:
        if not self.latest_check:
            return {}
        return json.loads(self.latest_check)

    @gl.public.view
    def get_check(self, check_id: int) -> typing.Any:
        if check_id < 1 or check_id > len(self.checks):
            raise ValueError("Check not found.")
        return json.loads(self.checks[check_id - 1])


def _normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    return parsed.netloc.replace("www.", "").split(":")[0]


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().split())


def _fingerprint(value: str) -> str:
    checksum = 0
    for index, char in enumerate(value):
        checksum = (checksum + ((index + 1) * ord(char))) % 1000000007
    return str(checksum)


def _changed_prefix_chars(previous: str, current: str) -> int:
    shared = 0
    limit = min(len(previous), len(current))
    while shared < limit and previous[shared] == current[shared]:
        shared += 1
    return max(len(previous), len(current)) - shared


def _parse_json_dict(json_str: str) -> dict:
    first_brace = json_str.find("{")
    last_brace = json_str.rfind("}")
    if first_brace == -1 or last_brace == -1 or last_brace < first_brace:
        raise ValueError("No JSON object found.")
    return json.loads(json_str[first_brace : last_brace + 1])


def _canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _validate_drift(
    value: dict,
    expected_policy_url: str,
    excerpt_changed: bool,
    minimum_changed_chars: int,
    changed_chars: int,
) -> None:
    if value.get("policy_url") != expected_policy_url:
        raise ValueError("Policy URL mismatch.")
    severity = value.get("severity")
    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid drift severity.")
    if excerpt_changed and severity == NO_CHANGE:
        raise ValueError("Changed excerpts cannot be marked NO_CHANGE.")
    if not excerpt_changed and severity != NO_CHANGE:
        raise ValueError("Unchanged excerpts must be marked NO_CHANGE.")
    if excerpt_changed and changed_chars < minimum_changed_chars:
        raise ValueError("Drift is below the configured change threshold.")
    requires_review = value.get("requires_review")
    if not isinstance(requires_review, bool):
        raise ValueError("requires_review must be a boolean.")
    if severity == NO_CHANGE and requires_review:
        raise ValueError("NO_CHANGE cannot require review.")
    if severity != NO_CHANGE and not requires_review:
        raise ValueError("Changed policies require review.")
    confidence = value.get("confidence")
    if not isinstance(confidence, int) or confidence < 0 or confidence > 100:
        raise ValueError("Invalid confidence.")
    if not isinstance(value.get("changed_sections"), list):
        raise ValueError("changed_sections must be a list.")
