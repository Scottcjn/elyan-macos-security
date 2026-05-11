# Contributing to Elyan Labs macOS Security Shield

Thanks for helping improve Elyan Labs macOS Security Shield. This project
provides configuration-based mitigations and monitoring for end-of-life macOS
systems, so contributions need to be careful about root-level behavior,
LaunchDaemon configuration, and user safety.

## Project Areas

- `scripts/elyan-audit.sh` scans macOS systems for exposed configuration and
  known risky states.
- `scripts/elyan-harden.sh` applies configuration-based mitigations.
- `scripts/elyan-monitor.sh` monitors for suspicious filesystem, kext, SUID,
  process, network, and login activity.
- `scripts/install.sh` performs the manual installation flow.
- `build-pkg.sh` builds the macOS installer package.
- `pkg-build/scripts/postinstall` runs after package installation.
- `LaunchDaemons/com.elyanlabs.security-monitor.plist` defines the root
  LaunchDaemon.
- `README.md`, `SECURITY_AUDIT.md`, and `BCOS.md` contain the public
  documentation and security context.

## Local Setup

Use macOS for behavior that depends on `launchctl`, `pkgbuild`, `productbuild`,
`csrutil`, `socketfilterfw`, or other Apple system tools.

Clone the repository and make scripts executable in your working tree:

```bash
git clone https://github.com/Scottcjn/elyan-macos-security.git
cd elyan-macos-security
chmod +x scripts/*.sh build-pkg.sh pkg-build/scripts/postinstall
```

Run scripts in a disposable VM or test machine when validating hardening or
installation behavior. These scripts can write to `/usr/local/bin`,
`/usr/local/share/elyan-security`, `/Library/LaunchDaemons`, `/var/db/elyan`,
and `/var/log/elyan`.

## Validation

Run the checks that match the files you changed and list the results in your
pull request.

- Documentation only:

  ```bash
  git diff --check
  ```

- Shell script syntax:

  ```bash
  for file in \
      build-pkg.sh \
      scripts/elyan-audit.sh \
      scripts/elyan-harden.sh \
      scripts/elyan-monitor.sh \
      scripts/install.sh \
      pkg-build/scripts/postinstall; do
    tr -d '\r' < "$file" | bash -n -
  done
  ```

- LaunchDaemon plist changes:

  ```bash
  plutil -lint LaunchDaemons/com.elyanlabs.security-monitor.plist
  ```

- Package build changes on macOS:

  ```bash
  ./build-pkg.sh
  ```

- Manual installer changes on a disposable macOS test host:

  ```bash
  sudo ./scripts/install.sh
  elyan-status
  sudo elyan-audit
  ```

Do not run hardening or installation tests on a workstation you cannot afford
to reconfigure. If you cannot test on macOS, say so clearly and provide the
static checks you did run.

## Safety and Scope

- Keep the project within configuration-based mitigations. Do not add code that
  modifies Apple system binaries, bypasses SIP, circumvents code signing, or
  distributes patched Apple code.
- Prefer reversible configuration changes and document how users can inspect or
  undo them.
- Treat every root-level command as security-sensitive. Quote paths and
  variables, avoid predictable temporary files, and preserve restrictive file
  ownership and permissions where possible.
- Do not add secrets, wallet addresses, private endpoints, local machine paths,
  or personal logs to the repository.
- Update README or audit documentation when a mitigation, warning, dependency,
  installed path, or LaunchDaemon behavior changes.
- Keep compatibility notes explicit for Catalina, Big Sur, Monterey, and newer
  macOS versions where behavior differs.

## Code Style

- Use POSIX-friendly shell patterns where practical, but keep `#!/bin/bash`
  behavior consistent with the existing scripts.
- Use `set -e` carefully and handle expected command failures with `|| true` or
  explicit checks.
- Keep user-facing command output concise and action-oriented.
- Validate root requirements before writing to system directories.
- For plist changes, keep labels, paths, ownership assumptions, and log paths in
  sync with installer and postinstall scripts.
- For package changes, keep generated installer resources aligned with
  `scripts/install.sh` so package and manual installation behave consistently.

## Pull Request Guidelines

Before opening a pull request:

1. Scope the change to one mitigation, script, installer path, or documentation
   topic when possible.
2. Run the relevant validation commands.
3. Include the macOS version and test environment for any runtime validation.
4. Explain whether the change affects audit-only behavior, hardening behavior,
   monitoring behavior, installation, or packaging.
5. Document any remaining limitations, especially when you only performed static
   validation.

Good pull requests make the safety impact clear, include concrete validation
results, and avoid broad rewrites unrelated to the change being proposed.
