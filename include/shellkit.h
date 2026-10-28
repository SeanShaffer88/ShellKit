/* ShellKit.dll - safe Windows shell integration behind a small C ABI.
 *
 * What it does: registers context-menu verbs, file associations
 * and URL protocol handlers in the Windows registry - as a PLAN
 * you can inspect first, an APPLY that first records everything
 * it is about to change, and a RESTORE that puts the registry
 * back exactly as it was.
 *
 * Safety shape (the point of the library):
 * - Writes go to HKEY_CURRENT_USER only. Never HKLM, never
 *   another user's hive. Elevation is never needed and never
 *   requested.
 * - Apply only ever touches keys under HKCU\Software\Classes
 *   (the shell registration area). A plan - even a hand-written
 *   or hostile one - cannot aim ShellKit anywhere else; the key
 *   paths are validated again at apply time.
 * - A plan is data. Applying a plan writes registry values; it
 *   never runs a command line found in the plan.
 * - Apply returns a backup JSON. Restore runs it and the
 *   registry returns to the state captured before apply -
 *   created keys deleted, overwritten values rewritten,
 *   deleted subtrees recreated. Keep the backup.
 *
 * Strings: all strings are UTF-8, NUL-terminated.
 *
 * Ownership: every char* result is caller-owned and must be
 * freed with sh_free_string(). sh_version() and sh_last_error()
 * return borrowed strings - do NOT free them.
 *
 * Errors: a NULL return (or a nonzero return from sh_restore)
 * means failure; sh_last_error() / sh_last_error_code() describe
 * it on the calling thread.
 *
 * Platforms: the planners (sh_plan_*, sh_remove_plan) are pure
 * and work everywhere. sh_apply / sh_restore do the real
 * registry work and are Windows-only; elsewhere they fail with
 * SH_ERR_NOT_SUPPORTED.
 *
 * Threading: calls are independent except for the thread-local
 * last-error. A plan or backup string may be used from any
 * thread once produced.
 */
#ifndef SHELLKIT_H
#define SHELLKIT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if defined(_WIN32) && defined(SH_BUILD)
#define SH_API __declspec(dllexport)
#elif defined(_WIN32)
#define SH_API __declspec(dllimport)
#else
#define SH_API
#endif

#define SH_OK 0
#define SH_ERR_INVALID_ARG 1
#define SH_ERR_NOT_SUPPORTED 2
#define SH_ERR_NOT_FOUND 3
#define SH_ERR_ACCESS_DENIED 4
#define SH_ERR_PLATFORM 5
#define SH_ERR_INTERNAL 6

/* Library version, e.g. "0.1.0". Borrowed string; do not free. */
SH_API const char *sh_version(void);

/* Last error message on this thread ("" when none). Borrowed. */
SH_API const char *sh_last_error(void);

/* Last SH_ERR_* code on this thread (SH_OK when none). */
SH_API int sh_last_error_code(void);

/* Free a caller-owned string returned by this library.
 * NULL is accepted and does nothing. */
SH_API void sh_free_string(char *p);

/* Plan a context-menu verb. Pure: no registry access.
 *
 * spec_json: one JSON object:
 *   {"target":"extension|file|folder|all",   (required)
 *    "extension":".txt",       (required when target="extension";
 *                               the dot is added if omitted)
 *    "verb":"openwithmyapp",                 (required)
 *    "label":"Open with MyApp",              (optional)
 *    "command":"\"C:\\Tools\\myapp.exe\" \"%1\"",  (required)
 *    "icon":"C:\\Tools\\myapp.exe,0",        (optional)
 *    "position":"top|bottom",                (optional)
 *    "legacy_disable":true}                  (optional)
 * Targets: "extension" registers under that extension's key,
 * "file" under * (all files), "folder" under Directory,
 * "all" under AllFilesystemObjects.
 * Verb names, extensions etc. are sanitized: backslashes,
 * slashes and control characters are rejected.
 * Unknown spec fields are rejected; duplicate keys in one JSON
 * object are a parse error.
 *
 * Returns caller-owned plan JSON (see PLAN FORMAT below), or
 * NULL + last-error. The plan carries a warning when the command
 * template contains no %1 placeholder. */
SH_API char *sh_plan_verb(const char *spec_json);

/* Plan a file association: an extension bound to a ProgID with
 * a friendly name and an open command.
 *
 * spec_json:
 *   {"extension":".myapp",                     (required)
 *    "progid":"MyApp.Document",                (required)
 *    "friendly_name":"MyApp Document",         (optional)
 *    "command":"\"C:\\Tools\\myapp.exe\" \"%1\"",  (required)
 *    "icon":"C:\\Tools\\myapp.exe,0"}          (optional)
 * Same sanitization, warning and error contract as
 * sh_plan_verb. */
SH_API char *sh_plan_association(const char *spec_json);

/* Plan a URL protocol handler.
 *
 * spec_json:
 *   {"scheme":"myapp",                         (required; must
 *                                 start with a letter)
 *    "command":"\"C:\\Tools\\myapp.exe\" \"%1\"",  (required)
 *    "label":"MyApp Link"}                     (optional; default
 *                            label is "URL:<scheme> Protocol")
 * The plan creates the scheme key under Software\Classes, sets
 * the "URL Protocol" marker value the shell requires, and the
 * shell\open\command. Same contract as sh_plan_verb. */
SH_API char *sh_plan_protocol(const char *spec_json);

/* Plan REMOVING a registration. The spec is the matching
 * registration spec plus a "kind" field:
 *   {"kind":"verb", "target":..., "extension":..., "verb":...}
 *   {"kind":"association", "extension":..., "progid":...}
 *   {"kind":"protocol", "scheme":...}
 * Only the identifying fields are required. Removing an
 * association unlinks the extension (deletes its default value)
 * and deletes the ProgID key; the extension key itself is left
 * in place. The returned plan is applied with sh_apply like any
 * other, so a removal is backed up and restorable too. */
SH_API char *sh_remove_plan(const char *spec_json);

/* PLAN FORMAT (returned by all four planners):
 *   {"version":1, "kind":"verb|association|protocol",
 *    "action":"register|remove", "root":"HKCU",
 *    "ops":[ <op>, ... ], "warnings":[ "...", ... ]}
 * An <op> is one of:
 *   {"op":"create_key","root":"HKCU","key":"Software\\Classes\\..."}
 *   {"op":"set_string","root":"HKCU","key":"...","name":"",
 *    "value":"..."}        (name "" = the key's default value;
 *                           an "expand":true field, produced only
 *                           inside backups, means REG_EXPAND_SZ)
 *   {"op":"delete_key","root":"HKCU","key":"..."}
 *   {"op":"delete_value","root":"HKCU","key":"...","name":""}
 * Key paths are relative to HKEY_CURRENT_USER and must stay
 * under Software\Classes.
 *
 * Apply a plan to the real registry (Windows only). Before the
 * first write, the current state of every touched key is read,
 * so the returned backup can undo the whole plan:
 *   {"version":1, "undo_ops":[ <op>, ... ]}
 * If an operation fails midway, the operations already applied
 * are rolled back before the error returns. Hand-written plans
 * are accepted if they follow the format above and stay inside
 * the boundary; anything else is SH_ERR_INVALID_ARG.
 * Returns caller-owned backup JSON, or NULL + last-error
 * (SH_ERR_NOT_SUPPORTED off Windows). SAVE THE BACKUP: it is
 * the only way back. */
SH_API char *sh_apply(const char *plan_json);

/* Undo an apply: run a backup's undo_ops in order, restoring
 * the registry state captured before that apply.
 * Returns SH_OK (0) on success or an SH_ERR_* code; the message
 * is in sh_last_error(). Windows only; elsewhere returns
 * SH_ERR_NOT_SUPPORTED. */
SH_API int sh_restore(const char *backup_json);

#ifdef __cplusplus
}
#endif
#endif
