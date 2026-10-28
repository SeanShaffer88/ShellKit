//! ShellKit — pure logic core. Platform access lives in
//! `platform`; the C ABI lives in `ffi`. Keep this module
//! OS-independent and tested.
//!
//! What the core does:
//! - **Planners** turn a small JSON spec (a context-menu verb, a
//!   file association, a URL protocol handler) into a *plan*: an
//!   ordered list of registry operations under HKEY_CURRENT_USER,
//!   nothing else. A plan is data. Planning never touches the
//!   registry and never executes anything.
//! - **Backup inversion** is pure: given a plan and a snapshot of
//!   the current registry state, it computes the undo operations
//!   that return the registry to exactly that state.
//! - **Execution** (`execute_with_backup` / `run_ops`) drives any
//!   [`RegistryBackend`]; the real backend (Windows advapi32) lives
//!   in `platform`, and the tests drive an in-memory fake.

pub mod ffi;
pub mod json;
pub mod platform;

#[cfg(test)]
mod tests;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

// Error codes (mirror include/shellkit.h).
pub const SH_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;

pub type ShResult<T> = Result<T, (i32, String)>;

fn invalid<T>(msg: impl Into<String>) -> ShResult<T> {
    Err((ERR_INVALID_ARG, msg.into()))
}

/// Escape a string for inclusion inside JSON double quotes.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Registry operations — the vocabulary of plans and backups.
// ---------------------------------------------------------------------------

/// One registry operation. Plans and backups are ordered lists of
/// these, serialized as JSON objects (see `to_value` / `from_value`).
/// Every operation is rooted at HKEY_CURRENT_USER and the key path
/// must live under `Software\Classes` — enforced when a plan or
/// backup is parsed for execution, not merely when one is built.
#[derive(Clone, Debug, PartialEq)]
pub enum RegOp {
    CreateKey {
        key: String,
    },
    SetString {
        key: String,
        name: String,
        value: String,
        /// Write as REG_EXPAND_SZ instead of REG_SZ. Planners never
        /// set this; backup inversion sets it when the value being
        /// restored originally had that type.
        expand: bool,
    },
    DeleteKey {
        key: String,
    },
    DeleteValue {
        key: String,
        name: String,
    },
}

impl RegOp {
    pub fn key(&self) -> &str {
        match self {
            RegOp::CreateKey { key }
            | RegOp::SetString { key, .. }
            | RegOp::DeleteKey { key }
            | RegOp::DeleteValue { key, .. } => key,
        }
    }

    pub fn to_value(&self) -> json::Value {
        use json::Value as V;
        match self {
            RegOp::CreateKey { key: k } => json::obj(vec![
                ("op", json::s("create_key")),
                ("root", json::s("HKCU")),
                ("key", json::s(k)),
            ]),
            RegOp::SetString {
                key: k,
                name,
                value,
                expand,
            } => {
                let mut pairs: Vec<(&str, V)> = vec![
                    ("op", json::s("set_string")),
                    ("root", json::s("HKCU")),
                    ("key", json::s(k)),
                    ("name", json::s(name)),
                    ("value", json::s(value)),
                ];
                if *expand {
                    pairs.push(("expand", json::b(true)));
                }
                json::obj(pairs)
            }
            RegOp::DeleteKey { key: k } => json::obj(vec![
                ("op", json::s("delete_key")),
                ("root", json::s("HKCU")),
                ("key", json::s(k)),
            ]),
            RegOp::DeleteValue { key: k, name } => json::obj(vec![
                ("op", json::s("delete_value")),
                ("root", json::s("HKCU")),
                ("key", json::s(k)),
                ("name", json::s(name)),
            ]),
        }
    }

    pub fn from_value(v: &json::Value) -> ShResult<RegOp> {
        let op = req_str(v, "op")?;
        if let Some(root) = v.get("root") {
            if root.as_str() != Some("HKCU") {
                return invalid(format!(
                    "unsupported registry root {:?}: ShellKit only ever writes HKEY_CURRENT_USER",
                    root.to_json()
                ));
            }
        }
        let key = req_str(v, "key")?;
        validate_key_path(&key)?;
        match op.as_str() {
            "create_key" => Ok(RegOp::CreateKey { key }),
            "set_string" => Ok(RegOp::SetString {
                key,
                name: req_str(v, "name")?,
                value: req_str(v, "value")?,
                expand: opt_bool(v, "expand")?.unwrap_or(false),
            }),
            "delete_key" => Ok(RegOp::DeleteKey { key }),
            "delete_value" => Ok(RegOp::DeleteValue {
                key,
                name: req_str(v, "name")?,
            }),
            other => invalid(format!("unknown registry op \"{other}\"")),
        }
    }
}

/// A snapshot of one key and all its subkeys: `(key path, values)`
/// pairs, parents before children, where each value is
/// `(name, data, was_expand_sz)`. `None` from a snapshot call means
/// the key does not exist.
pub type SubtreeSnapshot = Vec<(String, Vec<(String, String, bool)>)>;

/// The registry surface the execution engine needs. The Windows
/// implementation is in `platform`; tests use an in-memory fake.
pub trait RegistryBackend {
    /// Read the full subtree rooted at `key`, or `None` if the key
    /// does not exist. Errors when a value cannot be represented
    /// (a non-string registry type): a backup that silently drops
    /// data is worse than no backup.
    fn snapshot(&mut self, key: &str) -> ShResult<Option<SubtreeSnapshot>>;
    fn create_key(&mut self, key: &str) -> ShResult<()>;
    fn set_string(&mut self, key: &str, name: &str, value: &str, expand: bool) -> ShResult<()>;
    fn delete_key(&mut self, key: &str) -> ShResult<()>;
    fn delete_value(&mut self, key: &str, name: &str) -> ShResult<()>;

    fn execute(&mut self, op: &RegOp) -> ShResult<()> {
        match op {
            RegOp::CreateKey { key } => self.create_key(key),
            RegOp::SetString {
                key,
                name,
                value,
                expand,
            } => self.set_string(key, name, value, *expand),
            RegOp::DeleteKey { key } => self.delete_key(key),
            RegOp::DeleteValue { key, name } => self.delete_value(key, name),
        }
    }
}

// ---------------------------------------------------------------------------
// Backup inversion (pure) and execution.
// ---------------------------------------------------------------------------

/// Invert one operation against a pre-execution snapshot lookup.
/// Returns the undo operations for this one operation, in the
/// order they must run relative to each other.
fn invert_op(op: &RegOp, snapshot: &dyn Fn(&str) -> Option<SubtreeSnapshot>) -> Vec<RegOp> {
    match op {
        RegOp::CreateKey { key } => {
            if snapshot(key).is_none() {
                vec![RegOp::DeleteKey { key: key.clone() }]
            } else {
                Vec::new()
            }
        }
        RegOp::SetString { key, name, .. } | RegOp::DeleteValue { key, name } => {
            let old = snapshot(key).and_then(|subtree| {
                subtree
                    .into_iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .and_then(|(_, values)| {
                        values
                            .into_iter()
                            .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
                    })
            });
            match old {
                Some((n, data, expand)) => vec![RegOp::SetString {
                    key: key.clone(),
                    name: n,
                    value: data,
                    expand,
                }],
                None => vec![RegOp::DeleteValue {
                    key: key.clone(),
                    name: name.clone(),
                }],
            }
        }
        RegOp::DeleteKey { key } => match snapshot(key) {
            None => Vec::new(),
            Some(subtree) => {
                let mut undo = Vec::new();
                for (path, values) in subtree {
                    undo.push(RegOp::CreateKey { key: path.clone() });
                    for (name, data, expand) in values {
                        undo.push(RegOp::SetString {
                            key: path.clone(),
                            name,
                            value: data,
                            expand,
                        });
                    }
                }
                undo
            }
        },
    }
}

/// Compute the full undo list for `ops` against a snapshot lookup:
/// the operations that, executed in the returned order, restore
/// the snapshotted state. Pure — this is the backup-inversion
/// function the tests exercise without any real registry.
pub fn invert_ops(ops: &[RegOp], snapshot: &dyn Fn(&str) -> Option<SubtreeSnapshot>) -> Vec<RegOp> {
    invert_ops_grouped(ops, snapshot)
        .into_iter()
        .rev()
        .flatten()
        .collect()
}

/// Per-operation undo groups, in plan order. Grouping matters:
/// the undo for one `delete_key` is a parents-first recreation
/// sequence that must not be interleaved or internally reversed;
/// only the group order reverses.
fn invert_ops_grouped(
    ops: &[RegOp],
    snapshot: &dyn Fn(&str) -> Option<SubtreeSnapshot>,
) -> Vec<Vec<RegOp>> {
    ops.iter().map(|op| invert_op(op, snapshot)).collect()
}

/// Execute `ops` against `backend`, returning the undo operations
/// (a backup) that restore the pre-execution state. Snapshots are
/// all taken before the first mutation, so the backup describes
/// exactly the state the caller started from. If an operation
/// fails midway, the operations already applied are rolled back
/// with their undo groups (best effort) before the error returns.
pub fn execute_with_backup(
    ops: &[RegOp],
    backend: &mut dyn RegistryBackend,
) -> ShResult<Vec<RegOp>> {
    let mut snaps: std::collections::HashMap<String, Option<SubtreeSnapshot>> =
        std::collections::HashMap::new();
    for op in ops {
        let k = op.key();
        if !snaps.contains_key(k) {
            let s = backend.snapshot(k)?;
            snaps.insert(k.to_string(), s);
        }
    }
    let lookup = |k: &str| snaps.get(k).cloned().flatten();
    let groups = invert_ops_grouped(ops, &lookup);
    for (i, op) in ops.iter().enumerate() {
        if let Err(e) = backend.execute(op) {
            for group in groups[..i].iter().rev() {
                for undo in group {
                    let _ = backend.execute(undo);
                }
            }
            return Err(e);
        }
    }
    Ok(groups.into_iter().rev().flatten().collect())
}

/// Execute `ops` with no backup (this is how a backup is restored:
/// its `undo_ops` run through here).
pub fn run_ops(ops: &[RegOp], backend: &mut dyn RegistryBackend) -> ShResult<()> {
    for op in ops {
        backend.execute(op)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sanitizers. Everything that becomes part of a registry key path
// passes through one of these; a rejected character here is a path
// injection stopped at the door.
// ---------------------------------------------------------------------------

fn reject_bad_chars(what: &str, s: &str) -> ShResult<()> {
    if s.is_empty() {
        return invalid(format!("{what} must not be empty"));
    }
    if let Some(c) = s
        .chars()
        .find(|c| *c == '\\' || *c == '/' || (*c as u32) < 0x20 || *c == '\u{7f}')
    {
        return invalid(format!(
            "{what} contains a forbidden character (U+{:04X}): backslashes, slashes and control characters are not allowed",
            c as u32
        ));
    }
    Ok(())
}

/// A context-menu verb name (the key name under `shell`).
pub fn sanitize_verb_name(raw: &str) -> ShResult<String> {
    if raw != raw.trim() {
        return invalid("verb name must not have leading or trailing whitespace");
    }
    reject_bad_chars("verb name", raw)?;
    if raw == "." || raw == ".." {
        return invalid("verb name must not be \".\" or \"..\"");
    }
    if raw.chars().count() > 128 {
        return invalid("verb name is longer than 128 characters");
    }
    Ok(raw.to_string())
}

/// A file extension, normalized to leading-dot form (`.txt`).
/// Input with or without the dot is accepted.
pub fn sanitize_extension(raw: &str) -> ShResult<String> {
    let body = raw.strip_prefix('.').unwrap_or(raw);
    reject_bad_chars("extension", body)?;
    if body.starts_with('.') {
        return invalid("extension must not start with more than one dot");
    }
    if !body
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+')
    {
        return invalid(
            "extension may only contain letters, digits, '-', '_' and '+' after the dot",
        );
    }
    if body.chars().count() > 64 {
        return invalid("extension is longer than 64 characters");
    }
    Ok(format!(".{body}"))
}

/// A ProgID such as `MyApp.Document.1`: dot-separated segments of
/// letters, digits, `-` and `_`, no leading/trailing/doubled dots.
pub fn sanitize_progid(raw: &str) -> ShResult<String> {
    reject_bad_chars("progid", raw)?;
    if raw.chars().count() > 128 {
        return invalid("progid is longer than 128 characters");
    }
    for seg in raw.split('.') {
        if seg.is_empty() {
            return invalid(
                "progid must not start or end with a dot or contain an empty segment (\"..\")",
            );
        }
        let mut chars = seg.chars();
        let first = chars.next().unwrap();
        if !first.is_ascii_alphanumeric() {
            return invalid("each progid segment must start with a letter or digit");
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return invalid("progid segments may only contain letters, digits, '-' and '_'");
        }
    }
    Ok(raw.to_string())
}

/// A URL scheme: a letter, then letters, digits, `+`, `-` or `.`.
pub fn sanitize_scheme(raw: &str) -> ShResult<String> {
    reject_bad_chars("scheme", raw)?;
    if raw.chars().count() > 64 {
        return invalid("scheme is longer than 64 characters");
    }
    let mut chars = raw.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() {
        return invalid("scheme must start with a letter");
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return invalid("scheme may only contain letters, digits, '+', '-' and '.'");
    }
    Ok(raw.to_string())
}

/// Validate a full key path from a plan/backup before execution:
/// rooted (implicitly) at HKCU, under `Software\Classes`, no
/// empty, `.` or `..` components, sane lengths. This is the
/// boundary that keeps `sh_apply` from being a general-purpose
/// registry writer: it can only ever touch shell registrations.
pub fn validate_key_path(key: &str) -> ShResult<()> {
    if key.is_empty() {
        return invalid("registry key path must not be empty");
    }
    if key.chars().count() > 1024 {
        return invalid("registry key path is longer than 1024 characters");
    }
    let parts: Vec<&str> = key.split('\\').collect();
    if parts.len() < 3
        || !parts[0].eq_ignore_ascii_case("Software")
        || !parts[1].eq_ignore_ascii_case("Classes")
    {
        return invalid(format!(
            "registry key path \"{key}\" is outside Software\\Classes: ShellKit only writes shell registrations under HKEY_CURRENT_USER"
        ));
    }
    for part in &parts {
        if part.is_empty() || *part == "." || *part == ".." {
            return invalid(format!(
                "registry key path \"{key}\" contains an empty, '.' or '..' component"
            ));
        }
        if part.chars().count() > 255 {
            return invalid(format!(
                "registry key path component in \"{key}\" is longer than 255 characters"
            ));
        }
        if part.chars().any(|c| (c as u32) < 0x20) {
            return invalid(format!(
                "registry key path \"{key}\" contains a control character"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Spec parsing helpers.
// ---------------------------------------------------------------------------

fn req_str(v: &json::Value, field: &str) -> ShResult<String> {
    match v.get(field) {
        Some(json::Value::Str(s)) => Ok(s.clone()),
        Some(other) => invalid(format!(
            "\"{field}\" must be a string, got {}",
            other.type_name()
        )),
        None => invalid(format!("missing required field \"{field}\"")),
    }
}

fn opt_str(v: &json::Value, field: &str) -> ShResult<Option<String>> {
    match v.get(field) {
        None | Some(json::Value::Null) => Ok(None),
        Some(json::Value::Str(s)) => Ok(Some(s.clone())),
        Some(other) => invalid(format!(
            "\"{field}\" must be a string, got {}",
            other.type_name()
        )),
    }
}

fn opt_bool(v: &json::Value, field: &str) -> ShResult<Option<bool>> {
    match v.get(field) {
        None | Some(json::Value::Null) => Ok(None),
        Some(json::Value::Bool(b)) => Ok(Some(*b)),
        Some(other) => invalid(format!(
            "\"{field}\" must be a boolean, got {}",
            other.type_name()
        )),
    }
}

fn reject_unknown(v: &json::Value, allowed: &[&str]) -> ShResult<()> {
    if let Some(pairs) = v.as_object() {
        for (k, _) in pairs {
            if !allowed.contains(&k.as_str()) {
                return invalid(format!("unknown field \"{k}\" in spec"));
            }
        }
    }
    Ok(())
}

fn parse_spec(spec_json: &str) -> ShResult<json::Value> {
    let v = json::parse(spec_json)
        .map_err(|e| (ERR_INVALID_ARG, format!("spec is not valid JSON: {e}")))?;
    if v.as_object().is_none() {
        return invalid("spec must be a JSON object");
    }
    Ok(v)
}

/// The `%1` warning: a shell command template without the
/// placeholder launches the program without telling it what to
/// open. A warning, not an error — fixed-argument commands are
/// legitimate — but it is the single most common verb mistake.
fn template_warnings(command: &str, warnings: &mut Vec<String>) {
    if !command.contains("%1") {
        warnings.push(
            "command template does not contain %1: the program will be launched without the selected file or URL as an argument"
                .to_string(),
        );
    }
}

const CLASSES: &str = "Software\\Classes";

fn plan_value(kind: &str, action: &str, ops: &[RegOp], warnings: &[String]) -> String {
    json::obj(vec![
        ("version", json::Value::I64(1)),
        ("kind", json::s(kind)),
        ("action", json::s(action)),
        ("root", json::s("HKCU")),
        (
            "ops",
            json::Value::Array(ops.iter().map(|o| o.to_value()).collect()),
        ),
        (
            "warnings",
            json::Value::Array(warnings.iter().map(|w| json::s(w)).collect()),
        ),
    ])
    .to_json()
}

// ---------------------------------------------------------------------------
// Planners.
// ---------------------------------------------------------------------------

/// The base key a verb hangs under, by spec target.
fn verb_base(spec: &json::Value) -> ShResult<String> {
    let target = req_str(spec, "target")?;
    match target.as_str() {
        "extension" => {
            let ext_raw = req_str(spec, "extension")?;
            let ext = sanitize_extension(&ext_raw)?;
            Ok(format!("{CLASSES}\\{ext}"))
        }
        "file" => Ok(format!("{CLASSES}\\*")),
        "folder" => Ok(format!("{CLASSES}\\Directory")),
        "all" => Ok(format!("{CLASSES}\\AllFilesystemObjects")),
        other => invalid(format!(
            "unknown verb target \"{other}\": expected \"extension\", \"file\", \"folder\" or \"all\""
        )),
    }
}

const VERB_FIELDS: &[&str] = &[
    "kind",
    "target",
    "extension",
    "verb",
    "label",
    "command",
    "icon",
    "position",
    "legacy_disable",
];

fn plan_verb_inner(spec: &json::Value, remove: bool) -> ShResult<String> {
    reject_unknown(spec, VERB_FIELDS)?;
    let base = verb_base(spec)?;
    let verb = sanitize_verb_name(&req_str(spec, "verb")?)?;
    let verb_key = format!("{base}\\shell\\{verb}");
    if remove {
        let ops = vec![RegOp::DeleteKey { key: verb_key }];
        return Ok(plan_value("verb", "remove", &ops, &[]));
    }
    let command = req_str(spec, "command")?;
    let mut warnings = Vec::new();
    template_warnings(&command, &mut warnings);
    let mut ops = vec![RegOp::CreateKey {
        key: verb_key.clone(),
    }];
    if let Some(label) = opt_str(spec, "label")? {
        // The (Default) value is the classic label; MUIVerb is the
        // modern one Explorer prefers. Set both to the same text.
        ops.push(RegOp::SetString {
            key: verb_key.clone(),
            name: String::new(),
            value: label.clone(),
            expand: false,
        });
        ops.push(RegOp::SetString {
            key: verb_key.clone(),
            name: "MUIVerb".to_string(),
            value: label,
            expand: false,
        });
    }
    if let Some(icon) = opt_str(spec, "icon")? {
        ops.push(RegOp::SetString {
            key: verb_key.clone(),
            name: "Icon".to_string(),
            value: icon,
            expand: false,
        });
    }
    if let Some(position) = opt_str(spec, "position")? {
        let value = match position.as_str() {
            "top" => "Top",
            "bottom" => "Bottom",
            other => {
                return invalid(format!(
                    "unknown position \"{other}\": expected \"top\" or \"bottom\""
                ))
            }
        };
        ops.push(RegOp::SetString {
            key: verb_key.clone(),
            name: "Position".to_string(),
            value: value.to_string(),
            expand: false,
        });
    }
    if opt_bool(spec, "legacy_disable")?.unwrap_or(false) {
        ops.push(RegOp::SetString {
            key: verb_key.clone(),
            name: "LegacyDisable".to_string(),
            value: String::new(),
            expand: false,
        });
    }
    let command_key = format!("{verb_key}\\command");
    ops.push(RegOp::CreateKey {
        key: command_key.clone(),
    });
    ops.push(RegOp::SetString {
        key: command_key,
        name: String::new(),
        value: command,
        expand: false,
    });
    Ok(plan_value("verb", "register", &ops, &warnings))
}

/// Plan registering (or, via `sh_remove_plan`, removing) a
/// context-menu verb. Spec fields are documented in the header.
pub fn plan_verb(spec_json: &str) -> ShResult<String> {
    plan_verb_inner(&parse_spec(spec_json)?, false)
}

const ASSOC_FIELDS: &[&str] = &[
    "kind",
    "extension",
    "progid",
    "friendly_name",
    "command",
    "icon",
];

fn plan_association_inner(spec: &json::Value, remove: bool) -> ShResult<String> {
    reject_unknown(spec, ASSOC_FIELDS)?;
    let ext = sanitize_extension(&req_str(spec, "extension")?)?;
    let progid = sanitize_progid(&req_str(spec, "progid")?)?;
    let ext_key = format!("{CLASSES}\\{ext}");
    let progid_key = format!("{CLASSES}\\{progid}");
    if remove {
        // Unlink first, then delete the ProgID key this
        // registration created. The extension key itself is NOT
        // deleted: other values may live under it that this
        // registration never owned.
        let ops = vec![
            RegOp::DeleteValue {
                key: ext_key,
                name: String::new(),
            },
            RegOp::DeleteKey { key: progid_key },
        ];
        return Ok(plan_value("association", "remove", &ops, &[]));
    }
    let command = req_str(spec, "command")?;
    let mut warnings = Vec::new();
    template_warnings(&command, &mut warnings);
    let mut ops = vec![
        RegOp::CreateKey {
            key: ext_key.clone(),
        },
        RegOp::SetString {
            key: ext_key,
            name: String::new(),
            value: progid.clone(),
            expand: false,
        },
        RegOp::CreateKey {
            key: progid_key.clone(),
        },
    ];
    if let Some(name) = opt_str(spec, "friendly_name")? {
        ops.push(RegOp::SetString {
            key: progid_key.clone(),
            name: String::new(),
            value: name,
            expand: false,
        });
    }
    if let Some(icon) = opt_str(spec, "icon")? {
        let icon_key = format!("{progid_key}\\DefaultIcon");
        ops.push(RegOp::CreateKey {
            key: icon_key.clone(),
        });
        ops.push(RegOp::SetString {
            key: icon_key,
            name: String::new(),
            value: icon,
            expand: false,
        });
    }
    let command_key = format!("{progid_key}\\shell\\open\\command");
    ops.push(RegOp::CreateKey {
        key: command_key.clone(),
    });
    ops.push(RegOp::SetString {
        key: command_key,
        name: String::new(),
        value: command,
        expand: false,
    });
    Ok(plan_value("association", "register", &ops, &warnings))
}

/// Plan a file association: extension → ProgID with a friendly
/// name and an `open` command.
pub fn plan_association(spec_json: &str) -> ShResult<String> {
    plan_association_inner(&parse_spec(spec_json)?, false)
}

const PROTOCOL_FIELDS: &[&str] = &["kind", "scheme", "command", "label"];

fn plan_protocol_inner(spec: &json::Value, remove: bool) -> ShResult<String> {
    reject_unknown(spec, PROTOCOL_FIELDS)?;
    let scheme = sanitize_scheme(&req_str(spec, "scheme")?)?;
    let scheme_key = format!("{CLASSES}\\{scheme}");
    if remove {
        let ops = vec![RegOp::DeleteKey { key: scheme_key }];
        return Ok(plan_value("protocol", "remove", &ops, &[]));
    }
    let command = req_str(spec, "command")?;
    let mut warnings = Vec::new();
    template_warnings(&command, &mut warnings);
    let label = opt_str(spec, "label")?.unwrap_or_else(|| format!("URL:{scheme} Protocol"));
    let command_key = format!("{scheme_key}\\shell\\open\\command");
    let ops = vec![
        RegOp::CreateKey {
            key: scheme_key.clone(),
        },
        RegOp::SetString {
            key: scheme_key.clone(),
            name: String::new(),
            value: label,
            expand: false,
        },
        RegOp::SetString {
            key: scheme_key.clone(),
            name: "URL Protocol".to_string(),
            value: String::new(),
            expand: false,
        },
        RegOp::CreateKey {
            key: command_key.clone(),
        },
        RegOp::SetString {
            key: command_key,
            name: String::new(),
            value: command,
            expand: false,
        },
    ];
    Ok(plan_value("protocol", "register", &ops, &warnings))
}

/// Plan a URL protocol handler: scheme key with the
/// `URL Protocol` marker value and an `open` command.
pub fn plan_protocol(spec_json: &str) -> ShResult<String> {
    plan_protocol_inner(&parse_spec(spec_json)?, false)
}

/// Plan removing a registration. The spec is the registration
/// spec plus `"kind": "verb" | "association" | "protocol"`;
/// only the identifying fields are required.
pub fn remove_plan(spec_json: &str) -> ShResult<String> {
    let spec = parse_spec(spec_json)?;
    let kind = req_str(&spec, "kind")?;
    match kind.as_str() {
        "verb" => plan_verb_inner(&spec, true),
        "association" => plan_association_inner(&spec, true),
        "protocol" => plan_protocol_inner(&spec, true),
        other => invalid(format!(
            "unknown kind \"{other}\": expected \"verb\", \"association\" or \"protocol\""
        )),
    }
}

// ---------------------------------------------------------------------------
// Apply / restore entry points.
// ---------------------------------------------------------------------------

fn parse_ops(v: &json::Value, field: &str) -> ShResult<Vec<RegOp>> {
    let arr = match v.get(field) {
        Some(json::Value::Array(items)) => items,
        Some(other) => {
            return invalid(format!(
                "\"{field}\" must be an array, got {}",
                other.type_name()
            ))
        }
        None => return invalid(format!("missing required field \"{field}\"")),
    };
    if arr.is_empty() {
        return invalid(format!("\"{field}\" must not be empty"));
    }
    arr.iter().map(RegOp::from_value).collect()
}

fn parse_plan(plan_json: &str) -> ShResult<Vec<RegOp>> {
    let v = json::parse(plan_json)
        .map_err(|e| (ERR_INVALID_ARG, format!("plan is not valid JSON: {e}")))?;
    if v.as_object().is_none() {
        return invalid("plan must be a JSON object");
    }
    if let Some(root) = v.get("root") {
        if root.as_str() != Some("HKCU") {
            return invalid(
                "plan root is not \"HKCU\": ShellKit only ever writes HKEY_CURRENT_USER",
            );
        }
    }
    parse_ops(&v, "ops")
}

/// Apply a plan: execute its operations against the real registry
/// (Windows only) and return the backup JSON — the undo operations
/// that restore the exact prior state. Keep the backup; it is the
/// only way back. On non-Windows this returns
/// `ERR_NOT_SUPPORTED`; planning and backup inversion are pure
/// and work everywhere.
pub fn apply(plan_json: &str) -> ShResult<String> {
    let ops = parse_plan(plan_json)?;
    let mut backend = platform::backend()?;
    let undo = execute_with_backup(&ops, &mut *backend)?;
    Ok(json::obj(vec![
        ("version", json::Value::I64(1)),
        (
            "undo_ops",
            json::Value::Array(undo.iter().map(|o| o.to_value()).collect()),
        ),
    ])
    .to_json())
}

/// Restore from a backup JSON produced by [`apply`]: runs its
/// undo operations in order. Windows only, like `apply`.
pub fn restore(backup_json: &str) -> ShResult<()> {
    let v = json::parse(backup_json)
        .map_err(|e| (ERR_INVALID_ARG, format!("backup is not valid JSON: {e}")))?;
    if v.as_object().is_none() {
        return invalid("backup must be a JSON object");
    }
    let ops = parse_ops(&v, "undo_ops")?;
    let mut backend = platform::backend()?;
    run_ops(&ops, &mut *backend)
}
