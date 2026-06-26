# Eval Case Format

This directory contains JSONL eval suites for the roadmap phases.

`parser-smoke.jsonl` cases focus on shell structure extraction. Each line includes a command and the structural features the parser/report should expose.

`agent-command-safety.jsonl` cases focus on safety decisions. Expected decisions are `allow`, `ask`, `deny`, and `allow_in_sandbox`. The `expected_effects`, `expected_flows`, and `expected_evidence` fields are intentionally concrete so eval failures can identify missing analysis, not just a wrong final label.

`adversarial: true` marks non-obvious cases that try to hide effects behind wrapper flags, dynamic shell constructs, config indirection, source/sink flows, or familiar developer commands.
