# PolicyDriftSentinel

PolicyDriftSentinel is a standalone GenLayer Intelligent Contract for watching public policies, terms, API specs, grant rules, or compliance pages for meaningful drift. It stores a deterministic fingerprint of a tracked excerpt, fetches the live page during each check, and only asks validators to classify semantic severity when the fingerprint actually changes.

This is useful for builders who depend on public rules that can silently change: payment policies, marketplace rules, API usage terms, eligibility criteria, security notices, grant requirements, or integration documentation.

## Why GenLayer

Policy drift is not just a hash problem. A hash can prove that text changed, but builders still need a shared interpretation of whether the change is cosmetic, operationally relevant, or high risk. GenLayer lets validators fetch the live page with `gl.get_webpage`, reason over the previous and current excerpts with `gl.exec_prompt`, and agree on a structured severity through `gl.eq_principle_prompt_comparative`.

The contract does not rely on prompts for critical safety rules. It uses deterministic checks before storage and baseline updates.

## State Design

- `watch_name`: human-readable watch label.
- `policy_url`: tracked public page.
- `allowed_domain`: deterministic domain allowlist for the tracked page.
- `baseline_hash`: current deterministic fingerprint.
- `baseline_excerpt`: tracked normalized excerpt.
- `minimum_changed_chars`: deterministic threshold for material checks.
- `checks`: append-only drift check history.
- `latest_check`: cached latest check.

## Deterministic Invariants

- The policy URL returned by validators must equal the configured policy URL.
- Unchanged fingerprints must produce `NO_CHANGE`.
- Changed fingerprints cannot produce `NO_CHANGE`.
- Changed text below `minimum_changed_chars` is rejected before storage.
- Any changed policy must set `requires_review` to true.
- `NO_CHANGE` cannot require review.

## Example Deploy Inputs

```text
watch_name: GenLayer Docs Watch
policy_url: https://docs.genlayer.com/
allowed_domain: docs.genlayer.com
baseline_excerpt: GenLayer is a blockchain with AI-powered smart contracts that natively connect to the internet and understand both code and natural language.
minimum_changed_chars: 20
```

## Example Write

```text
check_policy()
```

## Files

- `contracts/policy_drift_sentinel.py`: standalone Intelligent Contract source.
- `tests/test_policy_drift_sentinel.py`: helper, structure, consensus, and invariant tests.
- `SUBMISSION.md`: concise submission notes.
