# Security Policy

## A note on what this project is

This repository contains **offensive security tooling** — a multi-agent red-team
platform — intended **solely for authorized penetration testing and security
research**. It is built to be operated only against systems you own or have
explicit, written permission to test. Every action is scope-checked and logged;
see the *Legal Notice* in the [README](README.md). Using this software against
systems without authorization is illegal.

This policy is about vulnerabilities **in this codebase itself** (the agents, the
orchestrator, the API server, the MCP layer), not about findings produced by the
tool during an engagement.

## Supported versions

Security fixes are applied to the `main` branch. There is no separate LTS branch;
please test against the latest `main`.

## Reporting a vulnerability

If you discover a security issue in this project — for example a way to bypass the
authorization scope gate, the guardrails, or the evidence chain; a secret-handling
flaw; an injection or SSRF in the API or MCP layer; or an unsafe default — please
report it privately:

1. Use GitHub's **Report a vulnerability** button under the repository's
   **Security** tab (Private Vulnerability Reporting), **or**
2. Open a minimal issue that says only "security report — please open a private
   channel" without disclosing details, and a maintainer will follow up.

Please include:

- the affected component and version (commit SHA),
- a description of the issue and its impact (e.g. scope-gate bypass, secret leak),
- reproduction steps or a proof of concept, and
- any suggested remediation.

**Please do not** open a public issue with exploit details, and do not test the
issue against infrastructure you are not authorized to touch.

## Handling expectations

- Acknowledgement of a report within a few business days.
- An initial assessment (severity, affected versions) once reproduced.
- A fix on `main` and credit to the reporter (unless you prefer to remain
  anonymous).

## Hardening notes for operators

- **Secrets:** keep real API keys and engagement data out of any cloud-synced
  working directory (see the OneDrive caveat in the project docs). Rotate any key
  that may have been exposed.
- **API server:** `/dashboard` and `/events` are unauthenticated by design for
  localhost use; bind to `127.0.0.1` and set `API_CORS_ORIGINS` to explicit
  origins before exposing the API on a network. Other routes require `x-api-key`
  when `API_SECRET_KEY` is set.
- **Dependencies:** CI runs `pip-audit` against the declared dependencies on every
  push; keep the build green.
- **Untrusted content:** agents read target-controlled output (banners, fetched
  pages, command results) — a prompt-injection vector (the *lethal trifecta*). Set
  `ENABLE_UNTRUSTED_CONTENT_DEFENSE=true` to detect injection attempts (recorded as
  findings) and spotlight tool output before it re-enters the model context.
  Defense-in-depth only — the scope gate, guardrails, and operator stay
  authoritative (`core/content_safety.py`, `docs/CAPABILITY_RESEARCH.md`).
