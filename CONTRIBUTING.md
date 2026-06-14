# Contributing to Warden Free

Thank you for your interest in `warden-free`.

This repository is the GPLv2-compatible Free edition of Warden Antivirus. It contains the ClamAV-based GUI shell and the `warden-clamav-bridge` companion executable. The Pro-only codebase lives elsewhere and is intentionally not part of this repository.

Current policy

- Bug reports and well-scoped technical suggestions are welcome.
- Security reports should be shared privately with the maintainer when possible.
- External pull requests are currently on hold until a contributor-rights / CLA policy exists.
- Until that policy exists, unsolicited PRs may be closed without merge even if the patch is technically correct.

Before you start

1. Read `README.md` for build requirements.
2. Read `docs/bridge-protocol.md` if your change touches the bridge request/response format.
3. Keep the GPL / proprietary boundary intact.

Repository scope

`warden-free` may include:

- the Qt6 desktop GUI for Free-safe flows
- ClamAV scan integration
- ClamAV definition update logic
- quarantine support used by the Free edition
- the GPL bridge protocol and bridge executable

`warden-free` must not include:

- Pro licensing logic
- Port Overseer / NVD network scanning
- Emergency Lockdown
- proprietary heuristics, custom DAT logic, or private tooling

Build setup

On Ubuntu / Linux Mint:

```bash
sudo apt install build-essential cmake qt6-base-dev libssl-dev libclamav-dev clamav-freshclam
./build.sh build
```

Coding expectations

- Use C++17 and existing Qt6 Widgets patterns already present in the repo.
- Keep changes small and explicit.
- Prefer process-safe argument APIs such as `QProcess::setProgram` / `setArguments`.
- Avoid introducing hidden coupling to `warden-pro`.
- Do not add dependencies on proprietary paths, private keys, or closed assets.
- Keep user-facing text concise and actionable.

ClamAV boundary rules

- `warden-free` is the only edition that may link against `libclamav` or `libfreshclam`.
- The bridge protocol must remain stable and documented.
- If you change bridge JSON fields, update `docs/bridge-protocol.md` in the same change.

Testing expectations

At minimum, validate the area you touched:

- `./build.sh build`
- Launch `./build.sh run` if the change affects UI behavior
- For updater changes, verify both success and failure paths render sensible status text
- For bridge changes, validate JSON handling for valid and invalid requests

Change review checklist

- Does the change stay inside the Free edition scope?
- Does it preserve the GPL boundary with Pro?
- Does it build cleanly with the documented Linux setup?
- Does it avoid hardcoded machine-specific paths?
- Does it avoid committing generated build output or runtime state?

Do not commit

- `build/`
- quarantine contents
- `.warden-data/`
- local caches or downloaded databases

Questions

If you are unsure whether a change belongs in Free or Pro, treat that as a design question first and resolve the boundary before writing code.
