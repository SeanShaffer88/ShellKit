//! C ABI surface — everything declared in include/shellkit.h.
//! Conventions (house standard):
//! - `*mut c_char` JSON results are caller-owned; free with
//!   `sh_free_string`.
//! - Failures return null (or, for `sh_restore`, the error code)
//!   and set the thread-local last error.
//! - Nothing unwinds across the FFI boundary (catch_unwind
//!   everywhere; release profile also sets panic = "abort").
//! - Planning functions are pure: they work on every platform and
//!   never touch the registry. `sh_apply` / `sh_restore` are
//!   Windows-only and return SH_ERR_NOT_SUPPORTED elsewhere.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

use crate::{ERR_INTERNAL, ERR_INVALID_ARG, SH_OK};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((0, CString::new("").unwrap()));
}

pub fn set_error(code: i32, msg: &str) {
    let clean: String = msg.chars().filter(|&c| c != '\0').collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(clean).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(SH_OK, "");
}

fn out_json(result: crate::ShResult<String>) -> *mut c_char {
    match result {
        Ok(text) => match CString::new(text) {
            Ok(s) => {
                clear_error();
                s.into_raw()
            }
            Err(_) => {
                set_error(ERR_INTERNAL, "result string contained a NUL byte");
                std::ptr::null_mut()
            }
        },
        Err((code, msg)) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
    }
}

fn cstr<'a>(ptr: *const c_char, what: &str) -> crate::ShResult<&'a str> {
    if ptr.is_null() {
        return Err((ERR_INVALID_ARG, format!("{what} must not be null")));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| (ERR_INVALID_ARG, format!("{what} must be valid UTF-8")))
}

fn guard_json<F: FnOnce() -> *mut c_char>(f: F) -> *mut c_char {
    match catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(p) => p,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            std::ptr::null_mut()
        }
    }
}

fn guard_code<F: FnOnce() -> c_int>(f: F) -> c_int {
    match catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(c) => c,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            ERR_INTERNAL as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn sh_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.2.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn sh_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn sh_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this
/// library returned and has not been freed yet. Documented in
/// the header.
#[no_mangle]
pub extern "C" fn sh_free_string(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

#[no_mangle]
pub extern "C" fn sh_plan_verb(spec_json: *const c_char) -> *mut c_char {
    guard_json(|| {
        let inner = cstr(spec_json, "spec_json").and_then(crate::plan_verb);
        out_json(inner)
    })
}

#[no_mangle]
pub extern "C" fn sh_plan_association(spec_json: *const c_char) -> *mut c_char {
    guard_json(|| {
        let inner = cstr(spec_json, "spec_json").and_then(crate::plan_association);
        out_json(inner)
    })
}

#[no_mangle]
pub extern "C" fn sh_plan_protocol(spec_json: *const c_char) -> *mut c_char {
    guard_json(|| {
        let inner = cstr(spec_json, "spec_json").and_then(crate::plan_protocol);
        out_json(inner)
    })
}

#[no_mangle]
pub extern "C" fn sh_plan_jump_list(spec_json: *const c_char) -> *mut c_char {
    guard_json(|| {
        let inner = cstr(spec_json, "spec_json").and_then(crate::plan_jump_list);
        out_json(inner)
    })
}

#[no_mangle]
pub extern "C" fn sh_remove_plan(spec_json: *const c_char) -> *mut c_char {
    guard_json(|| {
        let inner = cstr(spec_json, "spec_json").and_then(crate::remove_plan);
        out_json(inner)
    })
}

#[no_mangle]
pub extern "C" fn sh_apply(plan_json: *const c_char) -> *mut c_char {
    guard_json(|| {
        let inner = cstr(plan_json, "plan_json").and_then(crate::apply);
        out_json(inner)
    })
}

#[no_mangle]
pub extern "C" fn sh_restore(backup_json: *const c_char) -> c_int {
    guard_code(|| {
        let inner = cstr(backup_json, "backup_json").and_then(crate::restore);
        match inner {
            Ok(()) => {
                clear_error();
                SH_OK as c_int
            }
            Err((code, msg)) => {
                set_error(code, &msg);
                code as c_int
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn take(p: *mut c_char) -> String {
        assert!(!p.is_null(), "expected a result string, got null");
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        sh_free_string(p);
        s
    }

    #[test]
    fn ffi_planners_end_to_end() {
        // Verb
        let plan = take(sh_plan_verb(
            cs(concat!(
                "{\"target\":\"extension\",\"extension\":\".txt\",",
                "\"verb\":\"openwithmyapp\",\"label\":\"Open with MyApp\",",
                "\"command\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}"
            ))
            .as_ptr(),
        ));
        let v = crate::json::parse(&plan).unwrap();
        assert_eq!(v.get("kind").unwrap().as_str(), Some("verb"));
        assert_eq!(v.get("action").unwrap().as_str(), Some("register"));
        assert_eq!(sh_last_error_code(), SH_OK as c_int);
        let ops = v.get("ops").unwrap().as_array().unwrap();
        assert!(ops
            .iter()
            .any(|o| o.get("op").unwrap().as_str() == Some("create_key")));

        // Association
        let plan = take(sh_plan_association(
            cs(concat!(
                "{\"extension\":\".myapp\",\"progid\":\"MyApp.Document\",",
                "\"friendly_name\":\"MyApp Document\",",
                "\"command\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}"
            ))
            .as_ptr(),
        ));
        let v = crate::json::parse(&plan).unwrap();
        assert_eq!(v.get("kind").unwrap().as_str(), Some("association"));

        // Protocol
        let plan = take(sh_plan_protocol(cs(
            "{\"scheme\":\"myapp\",\"command\":\"\\\"C:\\\\Tools\\\\myapp.exe\\\" \\\"%1\\\"\"}",
        ).as_ptr()));
        let v = crate::json::parse(&plan).unwrap();
        assert_eq!(v.get("kind").unwrap().as_str(), Some("protocol"));

        // Remove plan
        let plan = take(sh_remove_plan(
            cs("{\"kind\":\"protocol\",\"scheme\":\"myapp\"}").as_ptr(),
        ));
        let v = crate::json::parse(&plan).unwrap();
        assert_eq!(v.get("action").unwrap().as_str(), Some("remove"));
    }

    #[test]
    fn ffi_null_and_bad_spec() {
        assert!(sh_plan_verb(std::ptr::null()).is_null());
        assert_eq!(sh_last_error_code(), ERR_INVALID_ARG as c_int);
        assert!(sh_plan_verb(cs("{\"target\":\"extension\"}").as_ptr()).is_null());
        assert_eq!(sh_last_error_code(), ERR_INVALID_ARG as c_int);
        assert!(sh_plan_protocol(cs("not json").as_ptr()).is_null());
        assert_eq!(sh_last_error_code(), ERR_INVALID_ARG as c_int);
        sh_free_string(std::ptr::null_mut()); // must be a no-op
    }

    #[test]
    fn ffi_apply_and_restore_platform_contract() {
        let plan = take(sh_plan_protocol(
            cs("{\"scheme\":\"myapp\",\"command\":\"app.exe \\\"%1\\\"\"}").as_ptr(),
        ));
        let backup = sh_apply(cs(&plan).as_ptr());
        #[cfg(not(windows))]
        {
            assert!(backup.is_null());
            assert_eq!(
                sh_last_error_code(),
                crate::ERR_NOT_SUPPORTED as c_int,
                "non-Windows apply must be a documented NOT_SUPPORTED"
            );
            assert_eq!(
                sh_restore(cs("{\"undo_ops\":[]}").as_ptr()),
                crate::ERR_INVALID_ARG as c_int,
                "empty undo_ops is an argument error on every platform"
            );
        }
        #[cfg(windows)]
        {
            // On Windows the protocol plan applies for real under
            // HKCU; clean up through the backup it returned.
            assert!(!backup.is_null());
            let backup = take(backup);
            assert_eq!(sh_restore(cs(&backup).as_ptr()), SH_OK as c_int);
        }
    }

    #[test]
    fn ffi_jump_list_contract() {
        // Planning is pure and works everywhere.
        let plan = take(sh_plan_jump_list(
            cs(concat!(
                "{\"app_id\":\"ShellKit.FfiTest\",\"tasks\":[",
                "{\"title\":\"Open\",\"target\":\"C:\\\\Tools\\\\myapp.exe\"}]}"
            ))
            .as_ptr(),
        ));
        let v = crate::json::parse(&plan).unwrap();
        assert_eq!(v.get("kind").unwrap().as_str(), Some("jump_list"));
        assert_eq!(sh_last_error_code(), SH_OK as c_int);
        // Bad specs fail the documented way.
        assert!(sh_plan_jump_list(std::ptr::null()).is_null());
        assert_eq!(sh_last_error_code(), ERR_INVALID_ARG as c_int);
        assert!(sh_plan_jump_list(cs("{\"app_id\":\"X\",\"tasks\":[]}").as_ptr()).is_null());
        assert_eq!(sh_last_error_code(), ERR_INVALID_ARG as c_int);

        let backup = sh_apply(cs(&plan).as_ptr());
        #[cfg(not(windows))]
        {
            assert!(backup.is_null());
            assert_eq!(sh_last_error_code(), crate::ERR_NOT_SUPPORTED as c_int);
            // Restoring a jump-list backup off Windows is the
            // same documented NOT_SUPPORTED (the backup shape is
            // validated first, so this is not an argument error).
            let rc = sh_restore(
                cs("{\"kind\":\"jump_list\",\"app_id\":\"ShellKit.FfiTest\",\"previous\":\"unknown\"}")
                    .as_ptr(),
            );
            assert_eq!(rc, crate::ERR_NOT_SUPPORTED as c_int);
            // A jump-list backup without an app_id is an
            // argument error on every platform.
            let rc = sh_restore(cs("{\"kind\":\"jump_list\"}").as_ptr());
            assert_eq!(rc, ERR_INVALID_ARG as c_int);
        }
        #[cfg(windows)]
        {
            // On Windows the apply talks to the real shell. If it
            // succeeds, restoring the backup (which clears the
            // list) must succeed too; if the environment refuses
            // (no interactive session, say), the failure must be
            // a platform error carrying the HRESULT, never a
            // fake success or an argument error — the plan was
            // valid. The runtime behaviour itself is only proven
            // by a real taskbar; see QUALITY.md.
            if backup.is_null() {
                assert_eq!(sh_last_error_code(), crate::ERR_PLATFORM as c_int);
            } else {
                let backup = take(backup);
                let bv = crate::json::parse(&backup).unwrap();
                assert_eq!(bv.get("kind").unwrap().as_str(), Some("jump_list"));
                assert_eq!(bv.get("previous").unwrap().as_str(), Some("unknown"));
                assert_eq!(sh_restore(cs(&backup).as_ptr()), SH_OK as c_int);
            }
        }
    }
}
