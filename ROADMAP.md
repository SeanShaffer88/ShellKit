# ShellKit Roadmap

## v0.2.0 (current)
Jump lists: `sh_plan_jump_list` plans an app's custom taskbar jump list — an Application User Model ID plus 1 to 10 tasks (title, absolute target, optional arguments / description / icon + icon index) — as a plan of `"kind":"jump_list"`. A jump list is not registry data, so the plan describes the apply instead of listing registry operations. `sh_apply` on Windows performs it through the `DestinationList` COM surface (hand-declared vtables, ole32 resolved at runtime, no new dependencies) and REPLACES the app's custom list wholesale. The backup is `{"kind":"jump_list","app_id":...,"previous":"unknown"}` — the previous list cannot be read back through COM — and restoring it clears the custom list (`DeleteList`). Off Windows the planner works everywhere and apply/restore return `SH_ERR_NOT_SUPPORTED`, exactly like the registry path. The planner, plan validation, backup shape and dispatch are unit-tested on every platform; the COM runtime itself is Unverified until a real Windows taskbar shows a list this kit set (see QUALITY.md).

## v0.1.0
Safe shell registration behind a C ABI: planners for context-menu verbs (extension / file / folder / all-files targets, label, icon, position, legacy-disable), file associations (extension → ProgID with friendly name, icon and open command), and URL protocol handlers (scheme key with the `URL Protocol` marker and open command). Plans are ordered registry operations under `HKCU\Software\Classes`. Apply is Windows-only, backup-first (full prior state, including deleted subtrees and original string value types), rolls back on mid-apply failure, and returns a backup JSON; restore replays it. Removal plans come from the same specs. Names are sanitized, command templates without `%1` draw a plan warning, and the planners + backup inversion are pure and tested on every platform against an in-memory fake registry.

## Next, in order
1. **Read-back inspection**: a `sh_inspect` call that reports which of a spec's registrations currently exist and whether their values match the plan — drift detection for installers and "repair my registration" flows.
2. **Open-with list entries**: planning for `OpenWithProgids` / `OpenWithList` entries so an app can offer itself as an alternative opener without claiming the default association.
3. **Default-association handoff helper**: detect when a per-user default was overridden by Windows' hash-protected `UserChoice` key and report it honestly (that key cannot be written directly; the helper would guide the user to the Settings page instead of faking a write).

## Explicitly not planned
- HKLM / all-users registration: ShellKit is per-user by design; elevation is never requested.
- Writing the hash-protected `UserChoice` key: Windows protects it precisely so programs cannot silently steal defaults; ShellKit will not forge its hash.
- Executing command templates to "verify" them: a plan is data, never a script.
- Packaged-app (MSIX) shell extensions: those are manifest-declared, not registry registrations.
