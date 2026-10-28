# ShellKit

## TL;DR

ShellKit is the safe way to put your program into Windows Explorer: a right-click menu entry, a file type that opens with your program, or a `yourapp://` link that launches it. Instead of poking the registry directly and hoping, you first get a **plan** — a plain list of exactly which registry keys and values would change, which you can read, show, or store. When you say go, ShellKit writes down the current state of everything it is about to touch, makes the change, and hands you a **backup**; feeding that backup back undoes the change completely, restoring even values that were there before. It only ever writes to the current user's registry area (no admin rights, no touching other users or system-wide settings), and applying a plan can never run a program — a plan is data, not a script. Since v0.2 it also sets your program's **jump list** — the task shortcuts on its taskbar button ("New Document", "Open Recent", and so on). A jump list is not registry data, so its plan describes the change instead of listing registry operations; applying it replaces the whole custom list, and because the previous list cannot be read back, its backup honestly says so and restoring it clears the list rather than pretending to bring the old one back.

```c
#include "shellkit.h"
#include <stdio.h>

int main(void) {
    /* 1. Plan: inspect before touching anything. */
    char *plan = sh_plan_protocol(
        "{\"scheme\":\"myapp\","
        "\"command\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}");
    printf("%s\n", plan);

    /* 2. Apply: writes under HKCU only, returns a backup. */
    char *backup = sh_apply(plan);
    sh_free_string(plan);
    if (!backup) { printf("error: %s\n", sh_last_error()); return 1; }
    /* ... save `backup` somewhere; it is the only way back ... */

    /* 3. Restore: registry returns to the pre-apply state. */
    int rc = sh_restore(backup);
    sh_free_string(backup);
    return rc;
}
```

## Key features

- **Plan before you touch anything.** `sh_plan_verb`, `sh_plan_association` and `sh_plan_protocol` turn a small JSON spec into a plan: an ordered list of registry operations (`create_key`, `set_string`, `delete_key`, `delete_value`) with exact `HKCU\Software\Classes\...` paths. Planning is pure — it works on any platform and never touches the registry.
- **Backup-first apply.** `sh_apply` reads the current state of every key the plan touches (including whole subtrees a `delete_key` would remove) *before* the first write, and returns a backup JSON of undo operations. If an operation fails midway, what was already applied is rolled back before the error returns.
- **Exact restore.** `sh_restore` runs a backup: keys the plan created are deleted, values it overwrote get their old contents back (including the original `REG_SZ` / `REG_EXPAND_SZ` type), and subtrees it deleted are recreated value by value. A backup that would have to guess — for example, a key containing a non-string value type it cannot represent — is refused up front instead of being taken lossily.
- **HKCU only, shell area only.** Writes are rooted at `HKEY_CURRENT_USER` and restricted to keys under `Software\Classes`. The boundary is enforced again when a plan is applied, so even a hand-written plan cannot aim ShellKit at the rest of the registry.
- **A plan is data, never a script.** Applying a plan writes registry values. Nothing in a plan or a backup is ever executed.
- **Sanitized names.** Verb names, extensions, ProgIDs and scheme names are validated before they become key paths: backslashes, slashes, control characters, leading dots where they would be wrong, empty ProgID segments and schemes that do not start with a letter are all rejected with a specific error.
- **Honest warnings.** A command template without the `%1` placeholder — the classic "my program opens but never gets the file" bug — produces a warning in the plan. It stays a warning, because fixed-argument commands are legitimate.
- **Removal is a plan too.** `sh_remove_plan` builds the delete plan for a registration from the same spec, so removing a verb, association or protocol is backed up and restorable exactly like registering one. Removing an association unlinks the extension and deletes the ProgID key; the extension key itself is left in place, because other values may live under it.
- **Jump lists (v0.2).** `sh_plan_jump_list` plans an app's custom taskbar jump list: an `app_id` (the Application User Model ID the app's windows carry) plus 1 to 10 tasks, each with a title, an absolute target path, and optional arguments, description (tooltip) and icon. Applying the plan replaces the app's custom jump list wholesale through the shell's DestinationList COM surface — the previous custom list is removed, not merged. The backup records `"previous":"unknown"` because the old list cannot be read back through COM; restoring it clears the custom list entirely, after which Windows shows its standard generated list.
- **Zero dependencies.** Hand-rolled JSON (duplicate keys in one object are a parse error, by design), hand-declared Win32 bindings (advapi32 linked; ole32 resolved at runtime for the jump-list COM work), small C ABI.

## The API in one screen

| Call | What it does |
|---|---|
| `sh_plan_verb(spec_json)` | Plan a context-menu verb; returns plan JSON |
| `sh_plan_association(spec_json)` | Plan an extension → ProgID association; returns plan JSON |
| `sh_plan_protocol(spec_json)` | Plan a URL protocol handler; returns plan JSON |
| `sh_remove_plan(spec_json)` | Plan removing a registration (`"kind"` field selects which) |
| `sh_plan_jump_list(spec_json)` | Plan an app's custom jump list (1–10 tasks); returns a `"kind":"jump_list"` plan |
| `sh_apply(plan_json)` | Apply a plan (Windows); returns backup JSON |
| `sh_restore(backup_json)` | Undo an apply from its backup; returns an `SH_*` code |
| `sh_version` / `sh_last_error` / `sh_last_error_code` / `sh_free_string` | Version, thread-local error, string ownership |

## What the plans look like

Registering a verb on `.txt` files produces ops like:

```json
{"op":"create_key","root":"HKCU","key":"Software\\Classes\\.txt\\shell\\openwithmyapp"}
{"op":"set_string","root":"HKCU","key":"Software\\Classes\\.txt\\shell\\openwithmyapp","name":"","value":"Open with MyApp"}
{"op":"create_key","root":"HKCU","key":"Software\\Classes\\.txt\\shell\\openwithmyapp\\command"}
{"op":"set_string","root":"HKCU","key":"Software\\Classes\\.txt\\shell\\openwithmyapp\\command","name":"","value":"\"C:\\Tools\\myapp.exe\" \"%1\""}
```

Verb targets: `extension` (that extension's key), `file` (`*`, all files), `folder` (`Directory`), `all` (`AllFilesystemObjects`). Optional verb fields: `label` (sets both the classic default value and `MUIVerb`), `icon`, `position` (`top` / `bottom`), `legacy_disable`.

An association creates the extension key pointing at the ProgID, the ProgID key with its friendly name, an optional `DefaultIcon`, and `shell\open\command`. A protocol creates the scheme key, sets its description and the `URL Protocol` marker value the shell requires, and `shell\open\command`.

A jump-list plan is not registry operations — a jump list lives behind the shell's COM surface, so the plan is the normalized task list itself:

```json
{"version":1,"kind":"jump_list","app_id":"MyCompany.MyApp","tasks":[{"title":"New Document","target":"C:\\Tools\\myapp.exe","args":"--new"}],"warnings":[]}
```

Applying it replaces the app's custom jump list with exactly these tasks. The app must run with the same `app_id` as its Application User Model ID for the shell to show the list on its taskbar button.

## Build

```sh
cargo build --release   # shell_kit.dll / .so / .a + include/shellkit.h
cargo test              # full test suite
```

Rust 1.80+, edition 2021, no dependencies. The planners and the backup-inversion logic build and test on any platform; `sh_apply` / `sh_restore` return `SH_ERR_NOT_SUPPORTED` off Windows.

## Limitations

- Per-user registrations only: there is deliberately no HKLM (all-users) mode.
- Values are strings (`REG_SZ`, and `REG_EXPAND_SZ` when restoring one). A subtree containing any other value type cannot be backed up, so an apply that would delete or overwrite it is refused rather than done lossily.
- Registrations are the classic `Software\Classes` kind. Packaged-app (MSIX) shell extensions, which are manifest-declared, are out of scope.
- Jump lists: at most 10 tasks (the shell's practical limit — more is a planner error, not a silent truncation); applying replaces the custom list wholesale; the previous custom list cannot be read back, so a jump-list backup restores by clearing the list, not by restoring the old tasks. Only the Tasks section is set; recent/frequent documents and custom categories remain the shell's own.
