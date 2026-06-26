# Evaluation

The eval suite is designed around high-risk false allows. A conservative `ask` can be annoying; an incorrect `allow` on secret exfiltration, destructive mutation, or downloaded-code execution is a trust failure.

## Suites

### Parser Smoke

`cases/parser-smoke.jsonl` checks that the parser/normalizer exposes shell structure that changes meaning:

- commands and argv,
- redirections,
- pipelines,
- chain operators,
- command and process substitutions,
- env assignments,
- unsupported constructs.

Run:

```bash
cargo run -- smoke --suite cases/parser-smoke.jsonl
```

Current result:

```text
24/24
```

### Command Safety

`cases/agent-command-safety.jsonl` checks policy decisions and expected evidence across benign, risky, and adversarial commands.

Run:

```bash
cargo run -- eval --suite cases/agent-command-safety.jsonl
```

Current result:

```text
101/101
high-risk false allows: 0
secret-to-network false allows: 0
destructive/infra false allows: 0
over-conservative: 0
```

## Categories

The command-safety suite covers:

- benign read-only commands,
- test and build commands,
- redirections outside the workspace,
- home dotfile writes,
- secret and credential reads,
- network upload/download cases,
- network-to-execution flows,
- dynamic shell execution,
- git mutation,
- package registry mutation,
- Docker, Kubernetes, cloud, and database mutation,
- argument injection and wrapper-flag escapes.

## Failure Semantics

The eval runner tracks:

- total pass/fail,
- false allows on high-risk commands,
- false allows on secret exfiltration,
- false allows on destructive or infrastructure mutation,
- over-conservative decisions on expected-allow cases.

The most important invariant is simple:

```text
No high-risk command in the suite should be allowed.
```

## Adding Cases

Add cases as JSONL records with:

- `id`
- `category`
- `adversarial`
- `command`
- `intent`
- `expected_decision`
- `expected_effects`
- `expected_flows`
- `expected_evidence`
- `rationale`

Prefer cases where the risky behavior is visible through structure: a redirect target, argv flag, nested shell string, command substitution, pipeline, or known source/sink flow.
