//! Core tests: planner goldens, sanitizer rejections, backup
//! inversion against an in-memory fake registry, and the
//! apply/restore boundary checks. Everything here is per-test
//! state — no shared statics (parallel tests must never see each
//! other's counts or registries).

use super::*;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// In-memory fake registry: the simulation backend. A key "exists"
// iff it has an entry in the map; creating a key makes an empty
// entry, deleting a key removes its whole subtree.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq)]
struct FakeRegistry {
    keys: BTreeMap<String, BTreeMap<String, String>>,
}

impl FakeRegistry {
    fn key_exists(&self, key: &str) -> bool {
        self.keys.contains_key(key)
    }
    fn get(&self, key: &str, name: &str) -> Option<&String> {
        self.keys.get(key).and_then(|m| m.get(name))
    }
    fn seed(&mut self, key: &str, name: &str, value: &str) {
        self.keys
            .entry(key.to_string())
            .or_default()
            .insert(name.to_string(), value.to_string());
    }
}

impl RegistryBackend for FakeRegistry {
    fn snapshot(&mut self, key: &str) -> ShResult<Option<SubtreeSnapshot>> {
        if !self.keys.contains_key(key) {
            return Ok(None);
        }
        let prefix = format!("{key}\\");
        let mut out: SubtreeSnapshot = Vec::new();
        for (k, values) in &self.keys {
            if k == key || k.starts_with(&prefix) {
                let vals = values
                    .iter()
                    .map(|(n, v)| (n.clone(), v.clone(), false))
                    .collect();
                out.push((k.clone(), vals));
            }
        }
        Ok(Some(out))
    }

    fn create_key(&mut self, key: &str) -> ShResult<()> {
        self.keys.entry(key.to_string()).or_default();
        Ok(())
    }

    fn set_string(&mut self, key: &str, name: &str, value: &str, _expand: bool) -> ShResult<()> {
        self.keys
            .entry(key.to_string())
            .or_default()
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn delete_key(&mut self, key: &str) -> ShResult<()> {
        let prefix = format!("{key}\\");
        self.keys.retain(|k, _| k != key && !k.starts_with(&prefix));
        Ok(())
    }

    fn delete_value(&mut self, key: &str, name: &str) -> ShResult<()> {
        if let Some(values) = self.keys.get_mut(key) {
            values.remove(name);
        }
        Ok(())
    }
}

fn plan_ops(plan_json: &str) -> Vec<RegOp> {
    let v = json::parse(plan_json).unwrap();
    v.get("ops")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| RegOp::from_value(o).unwrap())
        .collect()
}

fn plan_warnings(plan_json: &str) -> Vec<String> {
    let v = json::parse(plan_json).unwrap();
    v.get("warnings")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Planner goldens — exact expected JSON, key for key.
// ---------------------------------------------------------------------------

#[test]
fn verb_plan_golden_extension_full() {
    let plan = plan_verb(
        r#"{"target":"extension","extension":"txt","verb":"openwithmyapp","label":"Open with MyApp","command":"\"C:\\Tools\\myapp.exe\" \"%1\"","icon":"C:\\Tools\\myapp.exe,0","position":"top","legacy_disable":true}"#,
    )
    .unwrap();
    let expected = concat!(
        "{\"version\":1,\"kind\":\"verb\",\"action\":\"register\",\"root\":\"HKCU\",\"ops\":[",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\",\"name\":\"\",\"value\":\"Open with MyApp\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\",\"name\":\"MUIVerb\",\"value\":\"Open with MyApp\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\",\"name\":\"Icon\",\"value\":\"C:\\\\Tools\\\\myapp.exe,0\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\",\"name\":\"Position\",\"value\":\"Top\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\",\"name\":\"LegacyDisable\",\"value\":\"\"},",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\\\\command\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.txt\\\\shell\\\\openwithmyapp\\\\command\",\"name\":\"\",\"value\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}",
        "],\"warnings\":[]}"
    );
    assert_eq!(plan, expected);
}

#[test]
fn verb_plan_targets_and_minimal() {
    // "file" target, no optional fields: create verb key, create
    // command key, set command. No label -> no default/MUIVerb ops.
    let plan = plan_verb(r#"{"target":"file","verb":"inspect","command":"inspector.exe \"%1\""}"#)
        .unwrap();
    let ops = plan_ops(&plan);
    assert_eq!(
        ops,
        vec![
            RegOp::CreateKey {
                key: "Software\\Classes\\*\\shell\\inspect".into()
            },
            RegOp::CreateKey {
                key: "Software\\Classes\\*\\shell\\inspect\\command".into()
            },
            RegOp::SetString {
                key: "Software\\Classes\\*\\shell\\inspect\\command".into(),
                name: String::new(),
                value: "inspector.exe \"%1\"".into(),
                expand: false,
            },
        ]
    );
    // folder and all targets land on their documented base keys.
    let plan =
        plan_verb(r#"{"target":"folder","verb":"inspect","command":"inspector.exe \"%1\""}"#)
            .unwrap();
    assert_eq!(
        plan_ops(&plan)[0],
        RegOp::CreateKey {
            key: "Software\\Classes\\Directory\\shell\\inspect".into()
        }
    );
    let plan =
        plan_verb(r#"{"target":"all","verb":"inspect","command":"inspector.exe \"%1\""}"#).unwrap();
    assert_eq!(
        plan_ops(&plan)[0],
        RegOp::CreateKey {
            key: "Software\\Classes\\AllFilesystemObjects\\shell\\inspect".into()
        }
    );
}

#[test]
fn verb_plan_warns_without_placeholder() {
    let plan =
        plan_verb(r#"{"target":"file","verb":"inspect","command":"inspector.exe"}"#).unwrap();
    let warnings = plan_warnings(&plan);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("%1"), "{warnings:?}");
    // "%1" unquoted also satisfies the check.
    let plan =
        plan_verb(r#"{"target":"file","verb":"inspect","command":"inspector.exe %1"}"#).unwrap();
    assert!(plan_warnings(&plan).is_empty());
}

#[test]
fn association_plan_golden() {
    let plan = plan_association(
        r#"{"extension":".myapp","progid":"MyApp.Document","friendly_name":"MyApp Document","command":"\"C:\\Tools\\myapp.exe\" \"%1\"","icon":"C:\\Tools\\myapp.exe,0"}"#,
    )
    .unwrap();
    let expected = concat!(
        "{\"version\":1,\"kind\":\"association\",\"action\":\"register\",\"root\":\"HKCU\",\"ops\":[",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.myapp\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\.myapp\",\"name\":\"\",\"value\":\"MyApp.Document\"},",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\MyApp.Document\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\MyApp.Document\",\"name\":\"\",\"value\":\"MyApp Document\"},",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\MyApp.Document\\\\DefaultIcon\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\MyApp.Document\\\\DefaultIcon\",\"name\":\"\",\"value\":\"C:\\\\Tools\\\\myapp.exe,0\"},",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\MyApp.Document\\\\shell\\\\open\\\\command\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\MyApp.Document\\\\shell\\\\open\\\\command\",\"name\":\"\",\"value\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}",
        "],\"warnings\":[]}"
    );
    assert_eq!(plan, expected);
}

#[test]
fn protocol_plan_golden() {
    let plan =
        plan_protocol(r#"{"scheme":"myapp","command":"\"C:\\Tools\\myapp.exe\" \"%1\""}"#).unwrap();
    let expected = concat!(
        "{\"version\":1,\"kind\":\"protocol\",\"action\":\"register\",\"root\":\"HKCU\",\"ops\":[",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\myapp\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\myapp\",\"name\":\"\",\"value\":\"URL:myapp Protocol\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\myapp\",\"name\":\"URL Protocol\",\"value\":\"\"},",
        "{\"op\":\"create_key\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\myapp\\\\shell\\\\open\\\\command\"},",
        "{\"op\":\"set_string\",\"root\":\"HKCU\",\"key\":\"Software\\\\Classes\\\\myapp\\\\shell\\\\open\\\\command\",\"name\":\"\",\"value\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}",
        "],\"warnings\":[]}"
    );
    assert_eq!(plan, expected);
    // An explicit label replaces the generated one.
    let plan =
        plan_protocol(r#"{"scheme":"myapp","label":"MyApp Link","command":"myapp.exe \"%1\""}"#)
            .unwrap();
    assert!(plan.contains("\"value\":\"MyApp Link\""), "{plan}");
}

#[test]
fn remove_plans_golden() {
    let plan = remove_plan(r#"{"kind":"verb","target":"folder","verb":"inspect"}"#).unwrap();
    let v = json::parse(&plan).unwrap();
    assert_eq!(v.get("action").unwrap().as_str(), Some("remove"));
    assert_eq!(
        plan_ops(&plan),
        vec![RegOp::DeleteKey {
            key: "Software\\Classes\\Directory\\shell\\inspect".into()
        }]
    );

    // Association removal unlinks the extension, then deletes
    // the ProgID key; the extension key itself survives.
    let plan =
        remove_plan(r#"{"kind":"association","extension":".myapp","progid":"MyApp.Document"}"#)
            .unwrap();
    assert_eq!(
        plan_ops(&plan),
        vec![
            RegOp::DeleteValue {
                key: "Software\\Classes\\.myapp".into(),
                name: String::new(),
            },
            RegOp::DeleteKey {
                key: "Software\\Classes\\MyApp.Document".into()
            },
        ]
    );

    let plan = remove_plan(r#"{"kind":"protocol","scheme":"myapp"}"#).unwrap();
    assert_eq!(
        plan_ops(&plan),
        vec![RegOp::DeleteKey {
            key: "Software\\Classes\\myapp".into()
        }]
    );

    // A full registration spec is also accepted for removal.
    let plan =
        remove_plan(r#"{"kind":"protocol","scheme":"myapp","command":"ignored.exe \"%1\""}"#)
            .unwrap();
    assert_eq!(plan_ops(&plan).len(), 1);
    // Unknown kind is an argument error.
    assert_eq!(
        remove_plan(r#"{"kind":"jump-list"}"#).unwrap_err().0,
        ERR_INVALID_ARG
    );
}

// ---------------------------------------------------------------------------
// Sanitizers.
// ---------------------------------------------------------------------------

#[test]
fn sanitizers_accept_normal_names() {
    assert_eq!(sanitize_extension("txt").unwrap(), ".txt");
    assert_eq!(
        sanitize_extension(".tar.gz").unwrap_err().0,
        ERR_INVALID_ARG
    );
    assert_eq!(sanitize_extension(".My-App_2+x").unwrap(), ".My-App_2+x");
    assert_eq!(
        sanitize_progid("MyApp.Document.1").unwrap(),
        "MyApp.Document.1"
    );
    assert_eq!(sanitize_progid("txtfile").unwrap(), "txtfile");
    assert_eq!(sanitize_scheme("myapp").unwrap(), "myapp");
    assert_eq!(sanitize_scheme("my-app+v2.1").unwrap(), "my-app+v2.1");
    assert_eq!(
        sanitize_verb_name("openwithmyapp").unwrap(),
        "openwithmyapp"
    );
    assert_eq!(
        sanitize_verb_name("Open With My App").unwrap(),
        "Open With My App"
    );
}

#[test]
fn sanitizers_reject_injection_and_bad_shapes() {
    // Path injection through any identifier is refused.
    for bad in ["a\\b", "a/b", "a\u{1}b", "a\u{7f}b"] {
        assert_eq!(
            sanitize_verb_name(bad).unwrap_err().0,
            ERR_INVALID_ARG,
            "{bad:?}"
        );
        assert_eq!(
            sanitize_extension(bad).unwrap_err().0,
            ERR_INVALID_ARG,
            "{bad:?}"
        );
        assert_eq!(
            sanitize_progid(bad).unwrap_err().0,
            ERR_INVALID_ARG,
            "{bad:?}"
        );
        assert_eq!(
            sanitize_scheme(bad).unwrap_err().0,
            ERR_INVALID_ARG,
            "{bad:?}"
        );
    }
    // Empties.
    for bad in ["", ".", ".."] {
        assert!(sanitize_extension(bad).is_err(), "{bad:?}");
    }
    assert!(sanitize_verb_name("").is_err());
    assert!(sanitize_verb_name("..").is_err());
    assert!(sanitize_verb_name(" padded").is_err());
    assert!(sanitize_verb_name("padded ").is_err());
    // Progid shape: leading dot (wrong here), trailing dot,
    // empty segment, segment starting with a symbol, spaces.
    for bad in [".MyApp", "MyApp.", "MyApp..Doc", "-MyApp.Doc", "My App.Doc"] {
        assert_eq!(
            sanitize_progid(bad).unwrap_err().0,
            ERR_INVALID_ARG,
            "{bad:?}"
        );
    }
    // Scheme must start with a letter.
    for bad in ["1app", "+app", "my app", "my_app"] {
        assert_eq!(
            sanitize_scheme(bad).unwrap_err().0,
            ERR_INVALID_ARG,
            "{bad:?}"
        );
    }
    // Extension with a space or a second leading dot.
    assert!(sanitize_extension(".my app").is_err());
    assert!(sanitize_extension("..txt").is_err());
}

#[test]
fn planner_rejects_bad_specs() {
    // Missing required field.
    assert_eq!(
        plan_verb(r#"{"target":"file","verb":"x"}"#).unwrap_err().0,
        ERR_INVALID_ARG
    );
    // Unknown field.
    assert_eq!(
        plan_verb(r#"{"target":"file","verb":"x","command":"a %1","surprise":1}"#)
            .unwrap_err()
            .0,
        ERR_INVALID_ARG
    );
    // Unknown target / position.
    assert!(plan_verb(r#"{"target":"desktop","verb":"x","command":"a %1"}"#).is_err());
    assert!(
        plan_verb(r#"{"target":"file","verb":"x","command":"a %1","position":"middle"}"#).is_err()
    );
    // Injection through a spec field is refused by the planner.
    assert!(plan_verb(
        r#"{"target":"extension","extension":".txt","verb":"evil\\..\\..","command":"a %1"}"#
    )
    .is_err());
    assert!(
        plan_association(r#"{"extension":".x","progid":"..\\evil","command":"a %1"}"#).is_err()
    );
    assert!(plan_protocol(r#"{"scheme":"a\\b","command":"a %1"}"#).is_err());
    // Not JSON / not an object.
    assert!(plan_verb("nope").is_err());
    assert!(plan_verb("[1,2]").is_err());
    // Wrong types.
    assert!(plan_verb(r#"{"target":"file","verb":"x","command":7}"#).is_err());
    assert!(plan_protocol(r#"{"scheme":"ok","command":"a %1","label":true}"#).is_err());
}

// ---------------------------------------------------------------------------
// JSON engine edge cases (family behaviour).
// ---------------------------------------------------------------------------

#[test]
fn json_escape_and_parse_edges() {
    assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    // Round-trip through the parser: escapes, unicode, surrogates.
    let v = json::parse(r#"{"k":"a\\b\"c\ndé😀","n":-12,"f":2.5,"a":[true,null]}"#).unwrap();
    assert_eq!(v.get("k").unwrap().as_str(), Some("a\\b\"c\ndé😀"));
    assert_eq!(v.get("n").unwrap().as_i64(), Some(-12));
    // Duplicate keys are a parse error by design.
    assert!(json::parse(r#"{"a":1,"a":2}"#).is_err());
    // Garbage is refused.
    for bad in [
        "",
        "{",
        "{\"a\":}",
        "{\"a\":1} trailing",
        "\"unterminated",
        "[1,]",
    ] {
        assert!(json::parse(bad).is_err(), "{bad:?}");
    }
    // Over-deep nesting is refused, not a stack overflow.
    let deep = "[".repeat(500) + &"]".repeat(500);
    assert!(json::parse(&deep).is_err());
    // Serialization escapes what the parser reads back.
    let original = "quote \" backslash \\ tab \t snowman ☃";
    let text = json::s(original).to_json();
    assert_eq!(json::parse(&text).unwrap().as_str(), Some(original));
}

// ---------------------------------------------------------------------------
// Backup inversion against the fake registry.
// ---------------------------------------------------------------------------

/// The full promise: start from a registry with pre-existing
/// state, apply a plan, then run the backup's undo ops — the
/// registry must be byte-for-byte the state it started in.
fn round_trip(plan_json: &str, fake: &mut FakeRegistry) {
    let before = fake.clone();
    let ops = plan_ops(plan_json);
    let undo = execute_with_backup(&ops, fake).unwrap();
    run_ops(&undo, fake).unwrap();
    assert_eq!(
        *fake, before,
        "plan -> apply -> restore did not return to the starting state"
    );
}

#[test]
fn inversion_round_trip_on_empty_registry() {
    let mut fake = FakeRegistry::default();
    round_trip(
        &plan_verb(r#"{"target":"extension","extension":".txt","verb":"openwithmyapp","label":"Open","command":"app.exe \"%1\""}"#).unwrap(),
        &mut fake,
    );
    round_trip(
        &plan_association(r#"{"extension":".myapp","progid":"MyApp.Document","friendly_name":"Doc","command":"app.exe \"%1\"","icon":"app.exe,0"}"#).unwrap(),
        &mut fake,
    );
    round_trip(
        &plan_protocol(r#"{"scheme":"myapp","command":"app.exe \"%1\""}"#).unwrap(),
        &mut fake,
    );
    // Remove plans are plans too: register, then remove with
    // backup, then restore the backup.
    let mut fake2 = FakeRegistry::default();
    let register = plan_protocol(r#"{"scheme":"myapp","command":"app.exe \"%1\""}"#).unwrap();
    run_ops(&plan_ops(&register), &mut fake2).unwrap();
    round_trip(
        &remove_plan(r#"{"kind":"protocol","scheme":"myapp"}"#).unwrap(),
        &mut fake2,
    );
}

#[test]
fn inversion_restores_overwritten_and_preexisting_state() {
    let mut fake = FakeRegistry::default();
    // Pre-existing state the plan will collide with: .txt already
    // points somewhere, with an unrelated value that must survive.
    fake.seed("Software\\Classes\\.txt", "", "oldtxtfile");
    fake.seed("Software\\Classes\\.txt", "Content Type", "text/plain");
    fake.seed("Software\\Classes\\oldtxtfile", "", "Old Handler");
    fake.seed(
        "Software\\Classes\\oldtxtfile\\shell\\open\\command",
        "",
        "old.exe \"%1\"",
    );
    let before = fake.clone();

    let plan = plan_association(
        r#"{"extension":".txt","progid":"MyApp.Document","friendly_name":"MyApp Text","command":"myapp.exe \"%1\""}"#,
    )
    .unwrap();
    let ops = plan_ops(&plan);
    let undo = execute_with_backup(&ops, &mut fake).unwrap();
    // Applied state is the new one...
    assert_eq!(
        fake.get("Software\\Classes\\.txt", "").map(|s| s.as_str()),
        Some("MyApp.Document")
    );
    assert_eq!(
        fake.get("Software\\Classes\\.txt", "Content Type")
            .map(|s| s.as_str()),
        Some("text/plain"),
        "unrelated value under a touched key must survive apply"
    );
    // ...and restore returns everything, including the old value
    // the plan overwrote and the key the plan created.
    run_ops(&undo, &mut fake).unwrap();
    assert_eq!(fake, before);
}

#[test]
fn inversion_of_delete_key_restores_whole_subtree() {
    let mut fake = FakeRegistry::default();
    fake.seed("Software\\Classes\\myapp", "", "URL:myapp Protocol");
    fake.seed("Software\\Classes\\myapp", "URL Protocol", "");
    fake.seed(
        "Software\\Classes\\myapp\\shell\\open\\command",
        "",
        "myapp.exe \"%1\"",
    );
    fake.seed(
        "Software\\Classes\\myapp\\shell\\open",
        "Icon",
        "myapp.exe,0",
    );
    let before = fake.clone();
    let ops = vec![RegOp::DeleteKey {
        key: "Software\\Classes\\myapp".into(),
    }];
    let undo = execute_with_backup(&ops, &mut fake).unwrap();
    assert!(!fake.key_exists("Software\\Classes\\myapp"));
    assert!(fake.keys.is_empty());
    run_ops(&undo, &mut fake).unwrap();
    assert_eq!(fake, before, "deleted subtree was not fully restored");
}

#[test]
fn invert_ops_pure_function_directly() {
    // The documented pure entry point: no backend, just a
    // snapshot closure over a fake map.
    let mut fake = FakeRegistry::default();
    fake.seed("Software\\Classes\\.abc", "", "existing.progid");
    let ops = vec![
        RegOp::SetString {
            key: "Software\\Classes\\.abc".into(),
            name: String::new(),
            value: "new.progid".into(),
            expand: false,
        },
        RegOp::CreateKey {
            key: "Software\\Classes\\new.progid".into(),
        },
    ];
    let cell = std::cell::RefCell::new(&mut fake);
    let snapshot = |k: &str| cell.borrow_mut().snapshot(k).unwrap();
    let undo = invert_ops(&ops, &snapshot);
    // Execution order: last op undone first.
    assert_eq!(
        undo,
        vec![
            RegOp::DeleteKey {
                key: "Software\\Classes\\new.progid".into()
            },
            RegOp::SetString {
                key: "Software\\Classes\\.abc".into(),
                name: String::new(),
                value: "existing.progid".into(),
                expand: false,
            },
        ]
    );
}

#[test]
fn failed_apply_rolls_back_what_it_did() {
    // A backend that refuses the third operation: everything the
    // first two did must be undone before the error surfaces.
    #[derive(Default)]
    struct Flaky {
        inner: FakeRegistry,
        calls: usize,
    }
    impl RegistryBackend for Flaky {
        fn snapshot(&mut self, key: &str) -> ShResult<Option<SubtreeSnapshot>> {
            self.inner.snapshot(key)
        }
        fn create_key(&mut self, key: &str) -> ShResult<()> {
            self.calls += 1;
            if self.calls == 3 {
                return Err((ERR_PLATFORM, "simulated failure".into()));
            }
            self.inner.create_key(key)
        }
        fn set_string(&mut self, k: &str, n: &str, v: &str, e: bool) -> ShResult<()> {
            self.calls += 1;
            if self.calls == 3 {
                return Err((ERR_PLATFORM, "simulated failure".into()));
            }
            self.inner.set_string(k, n, v, e)
        }
        fn delete_key(&mut self, key: &str) -> ShResult<()> {
            self.inner.delete_key(key)
        }
        fn delete_value(&mut self, key: &str, name: &str) -> ShResult<()> {
            self.inner.delete_value(key, name)
        }
    }
    let mut flaky = Flaky::default();
    let plan = plan_protocol(r#"{"scheme":"myapp","command":"app.exe \"%1\""}"#).unwrap();
    let ops = plan_ops(&plan);
    let err = execute_with_backup(&ops, &mut flaky).unwrap_err();
    assert_eq!(err.0, ERR_PLATFORM);
    assert!(
        flaky.inner.keys.is_empty(),
        "partial apply was not rolled back: {:?}",
        flaky.inner.keys
    );
}

// ---------------------------------------------------------------------------
// Apply/restore input boundary (the part that runs everywhere).
// ---------------------------------------------------------------------------

#[test]
fn apply_rejects_plans_outside_the_shell_area() {
    // A hand-written plan aiming outside Software\Classes, or at
    // another hive, is refused before any platform call — so this
    // holds on every platform, including non-Windows.
    for bad in [
        r#"{"ops":[{"op":"create_key","root":"HKCU","key":"Software\\Microsoft\\Windows\\CurrentVersion\\Run"}]}"#,
        r#"{"ops":[{"op":"create_key","root":"HKLM","key":"Software\\Classes\\.txt"}]}"#,
        r#"{"ops":[{"op":"delete_key","key":"Software\\Classes\\..\\Microsoft"}]}"#,
        r#"{"ops":[{"op":"explode","key":"Software\\Classes\\.txt"}]}"#,
        r#"{"ops":[]}"#,
        r#"{"nope":1}"#,
        "not json",
    ] {
        assert_eq!(apply(bad).unwrap_err().0, ERR_INVALID_ARG, "{bad}");
    }
    // The key-path validator on its own.
    assert!(validate_key_path("Software\\Classes\\.txt\\shell\\open").is_ok());
    assert!(validate_key_path("software\\classes\\.txt").is_ok());
    assert!(validate_key_path("Software\\Classes").is_err()); // needs a subkey
    assert!(validate_key_path("Software\\Microsoft").is_err());
    assert!(validate_key_path("").is_err());
}

#[test]
fn key_paths_in_generated_plans_are_all_in_bounds() {
    // Every key every planner emits passes the execution-side
    // validator — planners and the apply boundary agree.
    let plans = [
        plan_verb(r#"{"target":"all","verb":"v","command":"a %1","label":"L","icon":"i","position":"bottom","legacy_disable":true}"#).unwrap(),
        plan_association(r#"{"extension":".x","progid":"X.Y","command":"a %1","friendly_name":"F","icon":"i"}"#).unwrap(),
        plan_protocol(r#"{"scheme":"x","command":"a %1"}"#).unwrap(),
        remove_plan(r#"{"kind":"association","extension":".x","progid":"X.Y"}"#).unwrap(),
    ];
    for plan in &plans {
        for op in plan_ops(plan) {
            validate_key_path(op.key()).unwrap();
        }
    }
}

#[test]
fn regop_json_round_trip() {
    let ops = vec![
        RegOp::CreateKey {
            key: "Software\\Classes\\.txt".into(),
        },
        RegOp::SetString {
            key: "Software\\Classes\\.txt".into(),
            name: String::new(),
            value: "a \"quoted\" \\ value".into(),
            expand: true,
        },
        RegOp::DeleteKey {
            key: "Software\\Classes\\.txt".into(),
        },
        RegOp::DeleteValue {
            key: "Software\\Classes\\.txt".into(),
            name: "X".into(),
        },
    ];
    for op in &ops {
        let back = RegOp::from_value(&op.to_value()).unwrap();
        assert_eq!(&back, op);
    }
    // A string op without "expand" parses as REG_SZ.
    let v =
        json::parse(r#"{"op":"set_string","key":"Software\\Classes\\.txt","name":"","value":"v"}"#)
            .unwrap();
    match RegOp::from_value(&v).unwrap() {
        RegOp::SetString { expand, .. } => assert!(!expand),
        other => panic!("wrong op: {other:?}"),
    }
}
