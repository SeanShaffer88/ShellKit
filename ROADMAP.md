# ShellKit Roadmap

## v0.1.0 (current)
Safe shell registration behind a C ABI: planners for context-menu verbs (extension / file / folder / all-files targets, label, icon, position, legacy-disable), file associations (extension → ProgID with friendly name, icon and open command), and URL protocol handlers (scheme key with the `URL Protocol` marker and open command). Plans are ordered registry operations under `HKCU\Software\Classes`. Apply is Windows-only, backup-first (full prior state, including deleted subtrees and original string value types), rolls back on mid-apply failure, and returns a backup JSON; restore replays it. Removal plans come from the same specs. Names are sanitized, command templates without `%1` draw a plan warning, and the planners + backup inversion are pure and tested on every platform against an in-memory fake registry.

## Next, in order
1. **Jump lists**: plan/apply support for per-app jump list destinations and tasks (the `DestinationList` COM surface, not registry values — a separate platform module behind the same plan/backup contract). Explicitly NOT in v0.1: the registry-op vocabulary cannot express it honestly, so v0.1 does not pretend to.
2. **Read-back inspection**: a `sh_inspect` call that reports which of a spec's registrations currently exist and whether their values match the plan — drift detection for installers and "repair my registration" flows.
3. **Open-with list entries**: planning for `OpenWithProgids` / `OpenWithList` entries so an app can offer itself as an alternative opener without claiming the default association.
4. **Default-association handoff helper**: detect when a per-user default was overridden by Windows' hash-protected `UserChoice` key and report it honestly (that key cannot be written directly; the helper would guide the user to the Settings page instead of faking a write).

## Explicitly not planned
- HKLM / all-users registration: ShellKit is per-user by design; elevation is never requested.
- Writing the hash-protected `UserChoice` key: Windows protects it precisely so programs cannot silently steal defaults; ShellKit will not forge its hash.
- Executing command templates to "verify" them: a plan is data, never a script.
- Packaged-app (MSIX) shell extensions: those are manifest-declared, not registry registrations.
