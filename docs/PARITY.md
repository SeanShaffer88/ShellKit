# ShellKit — Parity (spec vs implementation)

Evidence: the Rust test suite in `src/tests.rs`, `src/ffi.rs`
and `src/json.rs` (25 tests, all passing at the v0.1.0 gate)
plus the header contract in `include/shellkit.h`. "Verified"
means a named test exercises the behaviour. The Windows
registry backend compiles under the `x86_64-pc-windows-msvc`
target at the gate but has never executed — every row that
needs a real registry is marked accordingly, not claimed.

| Spec feature | Status | Evidence |
|---|---|---|
| Verb planner: targets extension / file (`*`) / folder (`Directory`) / all (`AllFilesystemObjects`) | Verified | `verb_plan_golden_extension_full`, `verb_plan_targets_and_minimal` |
| Verb options: label (default value + `MUIVerb`), icon, position top/bottom, legacy-disable | Verified | `verb_plan_golden_extension_full` (all options at once, exact JSON) |
| Association planner: extension → ProgID, friendly name, DefaultIcon, `shell\open\command` | Verified | `association_plan_golden` |
| Protocol planner: scheme key, description (generated `URL:<scheme> Protocol` or explicit label), `URL Protocol` marker, open command | Verified | `protocol_plan_golden` |
| Remove plans from the same specs + `kind` | Verified | `remove_plans_golden` (incl. association unlink-then-delete-ProgID, extension key preserved) |
| Command template without `%1` → plan warning | Verified | `verb_plan_warns_without_placeholder` (both `"%1"` and `%1` satisfy) |
| Sanitizers: verb / extension (dot-normalizing) / ProgID / scheme reject backslashes, slashes, control chars, leading dots where wrong, empty segments, non-letter scheme start | Verified | `sanitizers_accept_normal_names`, `sanitizers_reject_injection_and_bad_shapes`, planner-level injection cases in `planner_rejects_bad_specs` |
| Backup inversion: plan → backup → restore returns to the exact prior state (simulated, in-memory fake registry) | Verified | `inversion_round_trip_on_empty_registry`, `inversion_restores_overwritten_and_preexisting_state` (overwritten value + unrelated value survival), `inversion_of_delete_key_restores_whole_subtree`, `invert_ops_pure_function_directly` |
| Mid-apply failure rolls back already-applied ops | Verified | `failed_apply_rolls_back_what_it_did` (backend failing on the third mutation leaves an empty registry) |
| Apply boundary: HKCU only, `Software\Classes` only, no `..`, unknown ops rejected, enforced at parse-for-execution on every platform | Verified | `apply_rejects_plans_outside_the_shell_area`, `key_paths_in_generated_plans_are_all_in_bounds`, `regop_json_round_trip` |
| JSON engine: duplicate keys are a parse error; escapes/surrogates/depth cap | Verified | `json_escape_and_parse_edges` + the `src/json.rs` suite |
| FFI: planners end-to-end, null/bad-spec errors, free-string contract | Verified | `ffi_planners_end_to_end`, `ffi_null_and_bad_spec` |
| FFI apply/restore off Windows: `SH_ERR_NOT_SUPPORTED`, no fake success | Verified | `ffi_apply_and_restore_platform_contract` (non-Windows branch) |
| Windows apply: RegCreateKeyExW / RegSetValueExW writes under HKCU | Implemented, Unverified | `src/platform.rs` compiles + clippies for `x86_64-pc-windows-msvc`; never linked or run — CI's Windows build + a field test are the evidence still owed |
| Windows backup read: RegOpenKeyExW / RegEnumValueW / RegEnumKeyExW subtree snapshot, incl. REG_EXPAND_SZ type preservation and refusal on non-string types | Implemented, Unverified | Same as above; the inversion logic it feeds is verified against the fake |
| Windows delete: RegDeleteTreeW / RegDeleteValueW | Implemented, Unverified | Same as above |

## Known gaps (also in README "Limitations")
- Jump lists are roadmap, not v0.1 (see ROADMAP.md item 1) — deliberately absent rather than faked through registry ops.
- Non-string registry values cannot be represented in a backup; a Windows apply whose delete/overwrite would touch one is refused by the snapshot step.
- No HKLM mode, no `UserChoice` writing — by design, not omission.
