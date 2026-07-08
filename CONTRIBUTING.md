# Contributing

Thanks for your interest in improving the Kakunin SDK.

## Ground rules

- **Solo-maintainer project (for now).** Best-effort support; triage target is one week. Small, focused PRs get reviewed fastest.
- **Security issues:** never open a public issue — see [SECURITY.md](./SECURITY.md).
- By contributing you agree that your contributions are licensed under Apache-2.0. A lightweight CLA check runs on your first PR.

## Development

```bash
npm ci          # or: pip install -e ".[dev]" for the Python SDK
npm test        # or: pytest tests/ -v
npm run typecheck  # or: mypy kakunin/
```

## Pull requests

1. Open an issue first for anything beyond a small fix — API surface changes need discussion.
2. Add or update tests for any behavior change.
3. Keep the public API backward compatible; breaking changes require a major-version discussion.
4. CI must be green: build, tests, type-check, dependency audit.

## What we're looking for

- Bug fixes with reproduction tests
- Framework integration examples (agent frameworks, web frameworks)
- Documentation improvements

## What belongs elsewhere

Features that touch the hosted platform (new API endpoints, compliance report formats, billing) are not implementable from this repository — open an issue to discuss and we'll route it.

## Claiming an issue

Before you start working on an issue, comment `/assign` on it — our bot assigns it
to you automatically. This prevents two people building the same thing (which has
already happened a couple of times). Changed your mind? Comment `/unassign`.
