# Contributing

Thanks for helping improve Elyan Labs macOS Security Shield. This project deals
with security hardening for legacy macOS systems, so contributions should be
careful, transparent, and easy to audit.

## Local Setup

Clone the repository:

```bash
git clone https://github.com/Scottcjn/elyan-macos-security.git
cd elyan-macos-security
```

Most project files are shell scripts, launchd configuration, packaging scripts,
and documentation. Before editing scripts, make sure they stay executable:

```bash
chmod +x scripts/*.sh build-pkg.sh
```

## Validation

For documentation-only changes, run:

```bash
git diff --check
```

For shell script changes, also run syntax checks:

```bash
bash -n scripts/*.sh
bash -n build-pkg.sh
```

If a change affects installation or launchd behavior, describe the macOS version
used for testing and include the exact commands you ran.

## Contribution Guidelines

- Use only documented Apple configuration and administration mechanisms.
- Do not modify Apple system binaries or bypass SIP, code signing, Gatekeeper,
  or other platform protections.
- Keep mitigations reversible and document any system settings they change.
- Prefer defensive configuration, auditing, monitoring, and clear operator
  instructions over invasive behavior.
- Update `README.md` or `SECURITY_AUDIT.md` when adding or changing a
  mitigation.
- Keep pull requests scoped to one mitigation, bug fix, packaging change, or
  documentation update.

## Pull Request Checklist

Before opening a pull request, include:

- a short summary of the change
- the affected macOS versions, if applicable
- validation commands and results
- any security tradeoffs or operational risks
- related issue or bounty links, when relevant

Security-sensitive changes should explain why the mitigation is safe, reversible,
and compatible with the project's legal notice.
