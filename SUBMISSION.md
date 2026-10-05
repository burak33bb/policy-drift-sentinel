# PolicyDriftSentinel Submission

PolicyDriftSentinel is a reusable GenLayer Intelligent Contract for policy and specification drift monitoring.

It differs from a basic validator because the contract maintains a baseline fingerprint and only invokes consensus when live content changes. GenLayer validators classify the semantic severity of the drift, while deterministic contract checks enforce URL identity, change/no-change consistency, review requirements, and materiality thresholds before storing the result or updating the baseline.

Tests cover helper behavior, state lifecycle, consensus usage, and deterministic invariants.
