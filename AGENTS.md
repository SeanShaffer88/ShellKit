# ShellKit — agent notes

- **HKCU only, never HKLM.** Every plan, backup and apply is rooted at HKEY_CURRENT_USER, and key paths are restricted to `Software\Classes` — validated in the planners AND again at apply time (`validate_key_path` / the root check in `RegOp::from_value` and `parse_plan`). Weakening either side of that double check turns `sh_apply` into a general-purpose registry writer; do not.
- **A plan is data — never execute a command line from a plan.** Command templates are registry *values* ShellKit writes. Nothing in a plan, a backup, or a spec is ever run, shelled out, or passed to a shell API. If a future feature seems to need that, it is a different feature with its own design, not a small change here.
- **Backup before mutation is load-bearing.** `execute_with_backup` snapshots every touched key before the first write, and a failed apply rolls back with the undo groups before returning its error. Taking snapshots lazily (after some ops have run) makes the backup describe a state that never existed.
- **Undo groups reverse as groups, never op-by-op across the whole list.** The undo for one `delete_key` is a parents-first recreation sequence; reversing it internally recreates children before parents. `invert_ops_grouped` exists for exactly this — keep the grouping.
- **Refuse a lossy backup.** The Windows snapshot errors on non-string value types instead of skipping them. "Backing up" a subtree while silently dropping a DWORD is worse than refusing the apply; do not soften that into a warning.
- **Association removal does not delete the extension key.** It unlinks (deletes the default value) and deletes the ProgID key. The extension key can hold values this registration never owned; deleting it would be destroying other software's state.
- **Sanitizers are the path-injection boundary.** Every spec field that becomes part of a key path passes a sanitizer in `lib.rs`. New planners or fields must do the same — never format a raw spec string into a key path.
- The JSON engine (src/json.rs) is the family design — duplicate keys in one object are a PARSE ERROR by design; do not "fix" that into last-wins.
- Jump lists are roadmap, NOT in v0.1 (see ROADMAP.md). Do not half-add them.
- Gate: WinDevKit tools/gate.sh (fmt + clippy both targets + full tests). Check/clippy do not link — CI's real Windows build is the link gate.
