# ShellKit — Quality Scorecard

Scored against the v0.1.0 gate run on the development VM:
`cargo fmt --check`, clippy (host + `x86_64-pc-windows-msvc`,
`-D warnings`), and the full test suite — 25/25 passing, gate
run repeated with the same result.
Scores are only claimed where that evidence exists; Windows
runtime behaviour is not claimed from Linux evidence.

| Dimension | Score /5 | Evidence |
|---|---|---|
| Planner correctness | 5 | Exact golden plan JSON asserted for a full verb, a minimal verb on every target, an association, a protocol (incl. generated and explicit labels), and all three remove plans |
| Backup & restore exactness | 5 | Plan → apply → restore against an in-memory fake registry returns the registry to the byte-identical starting state: on an empty registry, over pre-existing colliding state, and for a whole deleted subtree; mid-apply failure rolls back fully |
| Safety boundary | 5 | Apply rejects plans aimed outside `Software\Classes`, at another root, or through `..` components before any platform call (tested on the host); sanitizers reject backslash/slash/control injection in every identifier kind |
| Sanitizers & spec validation | 5 | Acceptance and rejection suites for verb names, extensions, ProgIDs, schemes; planners reject missing/unknown/mistyped fields and non-object specs |
| API & documentation | 4 | Header documents every export with semantics, the plan format, error codes and ownership; README has a runnable C example. No compiled C consumer test in the suite (FFI is exercised from Rust) — one point held back |
| Code health | 5 | Zero dependencies, fmt + clippy clean on both targets at the gate, no unwinding across the FFI boundary, no shared mutable state across tests |
| Platform coverage | 2 | Planners, inversion, FFI contract and the NOT_SUPPORTED path are fully tested on Linux, and the Windows backend compiles + clippies under the MSVC target — but no Windows machine or CI run has yet linked the DLL or executed a real registry apply/restore. Honestly low until that happens |

**Total: 83/100**

## Waivers / open items
- **Windows registry apply/restore is Unverified.** The advapi32 backend (snapshot via RegOpenKeyExW/RegEnumValueW/RegEnumKeyExW, writes via RegCreateKeyExW/RegSetValueExW/RegDeleteTreeW/RegDeleteValueW) has never run. First Windows CI run (link + the FFI test's real apply/restore path) and a field check are the follow-ups that can raise Platform coverage.
- A local Windows cross-link could not be attempted: the development VM has no MinGW linker installed. CI's `cargo build --release` on windows-latest is the link gate.
- No dimension is scored on Windows runtime evidence.
