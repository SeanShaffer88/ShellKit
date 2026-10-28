//! Platform layer: the only place Windows APIs are touched.
//! On non-Windows targets `backend()` returns ERR_NOT_SUPPORTED so
//! the pure logic (planning + backup inversion) and the FFI
//! contract stay testable anywhere.
//!
//! Every extern block MUST carry #[link(name = "...")] naming its
//! import library. Without it the build fails at LINK time with
//! LNK2019 — check and clippy cannot catch it; CI's real build can.
//!
//! The Windows backend writes HKEY_CURRENT_USER only. Key paths
//! arriving here have already been validated by the core to live
//! under `Software\Classes`.

use crate::{RegistryBackend, ShResult};

/// Construct the real registry backend. On non-Windows there is
/// none: apply/restore are documented NOT_SUPPORTED there.
#[cfg(windows)]
pub fn backend() -> ShResult<Box<dyn RegistryBackend>> {
    Ok(Box::new(win::WinRegistry))
}

#[cfg(not(windows))]
pub fn backend() -> ShResult<Box<dyn RegistryBackend>> {
    Err((
        crate::ERR_NOT_SUPPORTED,
        "applying a plan is only available on Windows (planning and backup inversion work on every platform)"
            .to_string(),
    ))
}

#[cfg(windows)]
mod win {
    use super::RegistryBackend;
    use crate::{ShResult, SubtreeSnapshot, ERR_ACCESS_DENIED, ERR_NOT_FOUND, ERR_PLATFORM};
    use std::ffi::c_void;

    type Hkey = *mut c_void;
    type Lstatus = i32;

    const HKEY_CURRENT_USER: usize = 0x8000_0001;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    const KEY_READ: u32 = 0x20019; // STANDARD_RIGHTS_READ | QUERY_VALUE | ENUMERATE_SUB_KEYS | NOTIFY
    const KEY_WRITE: u32 = 0x20006; // STANDARD_RIGHTS_WRITE | SET_VALUE | CREATE_SUB_KEY
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_MORE_DATA: i32 = 234;
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    /// Bounds for subtree snapshots: registration subtrees are
    /// small; the caps keep a hostile or corrupt tree from turning
    /// a snapshot into unbounded work.
    const MAX_DEPTH: usize = 32;
    const MAX_KEYS: usize = 4096;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hkey: Hkey,
            subkey: *const u16,
            reserved: u32,
            class: *const u16,
            options: u32,
            sam_desired: u32,
            security_attributes: *const c_void,
            result: *mut Hkey,
            disposition: *mut u32,
        ) -> Lstatus;
        fn RegOpenKeyExW(
            hkey: Hkey,
            subkey: *const u16,
            options: u32,
            sam_desired: u32,
            result: *mut Hkey,
        ) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
        fn RegSetValueExW(
            hkey: Hkey,
            value_name: *const u16,
            reserved: u32,
            value_type: u32,
            data: *const u8,
            data_len: u32,
        ) -> Lstatus;
        fn RegEnumValueW(
            hkey: Hkey,
            index: u32,
            value_name: *mut u16,
            value_name_len: *mut u32,
            reserved: *mut u32,
            value_type: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> Lstatus;
        fn RegEnumKeyExW(
            hkey: Hkey,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_len: *mut u32,
            last_write: *mut c_void,
        ) -> Lstatus;
        fn RegDeleteTreeW(hkey: Hkey, subkey: *const u16) -> Lstatus;
        fn RegDeleteValueW(hkey: Hkey, value_name: *const u16) -> Lstatus;
    }

    fn hkcu() -> Hkey {
        HKEY_CURRENT_USER as Hkey
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Value-name pointer: the registry's (Default) value is
    /// addressed with a NULL name, not an empty string.
    fn name_ptr(name: &str, buf: &mut Vec<u16>) -> *const u16 {
        if name.is_empty() {
            std::ptr::null()
        } else {
            *buf = wide(name);
            buf.as_ptr()
        }
    }

    fn reg_err(rc: Lstatus, what: &str) -> (i32, String) {
        match rc {
            ERROR_ACCESS_DENIED => (
                ERR_ACCESS_DENIED,
                format!("{what}: access denied (Windows error 5)"),
            ),
            ERROR_FILE_NOT_FOUND => (
                ERR_NOT_FOUND,
                format!("{what}: key or value not found (Windows error 2)"),
            ),
            _ => (ERR_PLATFORM, format!("{what}: Windows error {rc}")),
        }
    }

    /// An opened key that closes itself.
    struct OpenKey(Hkey);
    impl Drop for OpenKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    fn create_key_handle(key: &str, sam: u32) -> ShResult<OpenKey> {
        let w = wide(key);
        let mut h: Hkey = std::ptr::null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                hkcu(),
                w.as_ptr(),
                0,
                std::ptr::null(),
                0,
                sam,
                std::ptr::null(),
                &mut h,
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(reg_err(rc, &format!("create/open key \"{key}\"")));
        }
        Ok(OpenKey(h))
    }

    /// Open an existing key; Ok(None) when it does not exist.
    fn open_key_handle(key: &str, sam: u32) -> ShResult<Option<OpenKey>> {
        let w = wide(key);
        let mut h: Hkey = std::ptr::null_mut();
        let rc = unsafe { RegOpenKeyExW(hkcu(), w.as_ptr(), 0, sam, &mut h) };
        match rc {
            ERROR_SUCCESS => Ok(Some(OpenKey(h))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            _ => Err(reg_err(rc, &format!("open key \"{key}\""))),
        }
    }

    fn utf16_lossy_trim_nul(units: &[u16]) -> String {
        let end = units
            .iter()
            .rposition(|&u| u != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        String::from_utf16_lossy(&units[..end])
    }

    /// Read all string values of one already-open key.
    fn read_values(h: Hkey, key_path: &str) -> ShResult<Vec<(String, String, bool)>> {
        let mut out = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 2048];
            let mut name_len = name_buf.len() as u32;
            let mut value_type: u32 = 0;
            let mut data_buf = vec![0u8; 8192];
            let mut data_len = data_buf.len() as u32;
            let mut rc = unsafe {
                RegEnumValueW(
                    h,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut value_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if rc == ERROR_MORE_DATA {
                // Grow to the reported sizes and retry this index.
                name_buf = vec![0u16; (name_len as usize) + 1];
                name_len = name_buf.len() as u32;
                data_buf = vec![0u8; data_len as usize];
                let mut dl = data_buf.len() as u32;
                rc = unsafe {
                    RegEnumValueW(
                        h,
                        index,
                        name_buf.as_mut_ptr(),
                        &mut name_len,
                        std::ptr::null_mut(),
                        &mut value_type,
                        data_buf.as_mut_ptr(),
                        &mut dl,
                    )
                };
                data_len = dl;
            }
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(reg_err(rc, &format!("enumerate values of \"{key_path}\"")));
            }
            let expand = match value_type {
                REG_SZ => false,
                REG_EXPAND_SZ => true,
                other => {
                    return Err((
                        ERR_PLATFORM,
                        format!(
                            "key \"{key_path}\" contains a value of registry type {other}, which a ShellKit backup cannot represent; refusing to proceed rather than back it up lossily"
                        ),
                    ))
                }
            };
            let name = utf16_lossy_trim_nul(&name_buf[..name_len as usize]);
            let units: Vec<u16> = data_buf[..data_len as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let data = utf16_lossy_trim_nul(&units);
            out.push((name, data, expand));
            index += 1;
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn snapshot_into(key: &str, depth: usize, out: &mut SubtreeSnapshot) -> ShResult<()> {
        if depth > MAX_DEPTH {
            return Err((
                ERR_PLATFORM,
                format!(
                    "key \"{key}\": subtree deeper than {MAX_DEPTH} levels; refusing to snapshot"
                ),
            ));
        }
        if out.len() >= MAX_KEYS {
            return Err((
                ERR_PLATFORM,
                format!("subtree at \"{key}\" exceeds {MAX_KEYS} keys; refusing to snapshot"),
            ));
        }
        let handle = match open_key_handle(key, KEY_READ | KEY_ENUMERATE_SUB_KEYS)? {
            Some(h) => h,
            None => return Ok(()),
        };
        let values = read_values(handle.0, key)?;
        out.push((key.to_string(), values));
        // Enumerate subkey names, then recurse (parents first:
        // this key was pushed before any descendant).
        let mut names = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut buf = vec![0u16; 256];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    handle.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(reg_err(rc, &format!("enumerate subkeys of \"{key}\"")));
            }
            names.push(utf16_lossy_trim_nul(&buf[..len as usize]));
            index += 1;
        }
        drop(handle);
        for name in names {
            snapshot_into(&format!("{key}\\{name}"), depth + 1, out)?;
        }
        Ok(())
    }

    pub struct WinRegistry;

    impl RegistryBackend for WinRegistry {
        fn snapshot(&mut self, key: &str) -> ShResult<Option<SubtreeSnapshot>> {
            if open_key_handle(key, KEY_QUERY_VALUE)?.is_none() {
                return Ok(None);
            }
            let mut out = Vec::new();
            snapshot_into(key, 0, &mut out)?;
            if out.is_empty() {
                // The key existed at the existence check but the
                // walk found nothing (deleted in between): report
                // the key itself with no values rather than None,
                // so inversion still protects it.
                out.push((key.to_string(), Vec::new()));
            }
            Ok(Some(out))
        }

        fn create_key(&mut self, key: &str) -> ShResult<()> {
            let _ = create_key_handle(key, KEY_WRITE)?;
            Ok(())
        }

        fn set_string(&mut self, key: &str, name: &str, value: &str, expand: bool) -> ShResult<()> {
            let handle = create_key_handle(key, KEY_WRITE | KEY_QUERY_VALUE)?;
            let mut name_buf = Vec::new();
            let np = name_ptr(name, &mut name_buf);
            let data = wide(value);
            let rc = unsafe {
                RegSetValueExW(
                    handle.0,
                    np,
                    0,
                    if expand { REG_EXPAND_SZ } else { REG_SZ },
                    data.as_ptr() as *const u8,
                    (data.len() * 2) as u32,
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(reg_err(rc, &format!("set value \"{name}\" in \"{key}\"")));
            }
            Ok(())
        }

        fn delete_key(&mut self, key: &str) -> ShResult<()> {
            let w = wide(key);
            let rc = unsafe { RegDeleteTreeW(hkcu(), w.as_ptr()) };
            match rc {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                _ => Err(reg_err(rc, &format!("delete key \"{key}\""))),
            }
        }

        fn delete_value(&mut self, key: &str, name: &str) -> ShResult<()> {
            let handle = match open_key_handle(key, KEY_SET_VALUE)? {
                Some(h) => h,
                None => return Ok(()),
            };
            let mut name_buf = Vec::new();
            let np = name_ptr(name, &mut name_buf);
            let rc = unsafe { RegDeleteValueW(handle.0, np) };
            match rc {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                _ => Err(reg_err(
                    rc,
                    &format!("delete value \"{name}\" in \"{key}\""),
                )),
            }
        }
    }
}
