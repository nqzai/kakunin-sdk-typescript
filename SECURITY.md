# Security Policy

Kakunin is compliance and identity infrastructure — we treat security reports with the highest priority.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@kakunin.ai** with:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept if possible)
- Affected package and version

You will receive an acknowledgment within **48 hours** and a triage decision within **5 business days**.

## Disclosure Policy

- We follow coordinated disclosure with a **90-day** window from report to public disclosure.
- We will credit reporters in release notes and our security acknowledgments page unless you prefer to remain anonymous.
- Please act in good faith: no data exfiltration, no service disruption, no testing against tenants that are not your own.

## Supported Versions

Only the latest published minor version of each SDK receives security fixes. Upgrade before reporting if possible.

## Scope

In scope: this SDK's source code and its published npm/PyPI artifacts.
Out of scope for this repository (report to security@kakunin.ai anyway, different track): the hosted Kakunin platform (api.kakunin.ai), dashboard, and infrastructure.
