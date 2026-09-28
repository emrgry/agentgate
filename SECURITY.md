# Security policy

AgentGate is a security boundary between AI agents and your machine, so we take reports
seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
"Report a vulnerability" button (Security → Advisories) on this repository.

Include what you found, how to reproduce it, and the impact you expect. We aim to
acknowledge reports within 3 working days.

## In scope

- Bypassing an approval: running a gated action without a valid phone-signed decision
- Forging or replaying decisions, commands, rekey or recovery proofs
- An agent disabling, reconfiguring or escaping AgentGate hooks
- Leaking secrets through logs, push notifications or the audit log
- Pairing or device-key attacks (MITM, key substitution)

## Out of scope

- Attacks that require root or a malicious user already at the keyboard
- Denial of service against your own local server
