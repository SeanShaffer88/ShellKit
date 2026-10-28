# ShellKit — Quality Scorecard

Scored against the v0.2.0 gate run on the development VM:
`cargo fmt --check`, clippy (host + `x86_64-pc-windows-msvc`,
`-D warnings`), and the full test suite — 33/33 passing, gate
run repeated with the same result.
Scores are only claimed where that evidence exists; Windows
runtime behaviour is not claimed from Linux evidence.

| Dimension | Score /5 | Evidence |
|---|---|---|
| Planner correctness | 5 | Exact golden plan JSON asserted for a full verb, a minimal verb on every target, an association, a protocol (incl. generated and explicit labels), all three remove plans, and the jump-list planner (full + minimal specs, icon-index normalization) |
| Backup & restore exactness | 5 | Plan → apply → restore against an in-memory fake registry returns the registry to the byte-identical starting state: on an empty registry, over pre-existing colliding state, and for a whole deleted subtree; mid-apply failure rolls back fully |
| Safety boundary | 5 | Apply rejects plans aimed outside `Software\Classes`, at another root, or through `..` components before any platform call (tested on the host); sanitizers reject backslash/slash/control injection in every identifier kind |
| Sanitizers & spec validation | 5 | Acceptance and rejection suites for verb names, extensions, ProgIDs, schemes; planners reject missing/unknown/mistyped fields and non-object specs |
| API & documentation | 4 | Header documents every export with semantics, the plan format, error codes and ownership; README has a runnable C example. No compiled C consumer test in the suite (FFI is exercised from Rust) — one point held back |
| Code health | 5 | Zero dependencies, fmt + clippy clean on both targets at the gate, no unwinding across the FFI boundary, no shared mutable state across tests |
| Platform coverage | 2 | Planners, inversion, FFI contract and the NOT_SUPPORTED path are fully tested on Linux, and the Windows backend (registry + the v0.2 jump-list COM module) compiles + clippies under the MSVC target — but no Windows machine or CI run has yet linked the DLL or executed a real registry apply/restore or jump-list apply. Honestly low until that happens |

**Total: 83/100**

## Waivers / open items
- **Windows registry apply/restore is Unverified.** The advapi32 backend (snapshot via RegOpenKeyExW/RegEnumValueW/RegEnumKeyExW, writes via RegCreateKeyExW/RegSetValueExW/RegDeleteTreeW/RegDeleteValueW) has never run. First Windows CI run (link + the FFI test's real apply/restore path) and a field check are the follow-ups that can raise Platform coverage.
- **Windows jump-list apply/restore is Unverified.** The COM sequence (ICustomDestinationList SetAppID → BeginList → per-task IShellLinkW + PKEY_Title property store → AddUserTasks → CommitList; restore via DeleteList) has never run against a real shell. The GUIDs and every vtable slot were checked against the `windows` crate's generated bindings before coding (sources cited in `src/platform.rs`), and every HRESULT failure surfaces in the error message in hex, but only a real Windows taskbar showing a list this kit set — and clearing it on restore — proves it. No score above reflects jump-list runtime evidence; the jump-list planner, validation, backup shape and off-Windows dispatch ARE covered by the Linux suite (8 of the 33 tests).
- A local Windows cross-link could not be attempted: the development VM has no MinGW linker installed. CI's `cargo build --release` on windows-latest is the link gate.
- No dimension is scored on Windows runtime evidence.
